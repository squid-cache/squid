/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 17    Request Forwarding */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/Address.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "anyp/PortCfg.h"
#include "CacheManager.h"
#include "CachePeer.h"
#include "client_side.h"
#include "clients/forward.h"
#include "clients/HttpTunneler.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "comm/Loops.h"
#include "CommCalls.h"
#include "errorpage.h"
#include "event.h"
#include "fd.h"
#include "fde.h"
#include "FwdState.h"
#include "globals.h"
#include "gopher.h"
#include "HappyConnOpener.h"
#include "hier_code.h"
#include "http.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "internal.h"
#include "ip/Intercept.h"
#include "ip/NfMarkConfig.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "ResolvedPeers.h"
#include "security/BlindPeerConnector.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "ssl/PeekingPeerConnector.h"
#include "Store.h"
#include "StoreClient.h"
#include "urn.h"
#include "whois.h"
#if USE_OPENSSL
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/ErrorDetail.h"
#include "ssl/helper.h"
#include "ssl/ServerBump.h"
#include "ssl/support.h"
#else
#include "security/EncryptorAnswer.h"
#endif

#include <cerrno>

static CLCB fwdServerClosedWrapper;

static OBJH fwdStats;

#define MAX_FWD_STATS_IDX 9
static int FwdReplyCodes[MAX_FWD_STATS_IDX + 1][Http::scInvalidHeader + 1];

PconnPool *fwdPconnPool = new PconnPool("server-peers", nullptr);

CBDATA_CLASS_INIT(FwdState);

class FwdStatePeerAnswerDialer: public CallDialer, public Security::PeerConnector::CbDialer
{
public:
    typedef void (FwdState::*Method)(Security::EncryptorAnswer &);

    FwdStatePeerAnswerDialer(Method method, FwdState *fwd):
        method_(method), fwd_(fwd), answer_() {}

    /* CallDialer API */
    virtual bool canDial(AsyncCall &call) { return fwd_.valid(); }
    void dial(AsyncCall &call) { ((&(*fwd_))->*method_)(answer_); }
    virtual void print(std::ostream &os) const {
        os << '(' << fwd_.get() << ", " << answer_ << ')';
    }

    /* Security::PeerConnector::CbDialer API */
    virtual Security::EncryptorAnswer &answer() { return answer_; }

private:
    Method method_;
    CbcPointer<FwdState> fwd_;
    Security::EncryptorAnswer answer_;
};

void
FwdState::abort(void* d)
{
    FwdState* fwd = (FwdState*)d;
    Pointer tmp = fwd; // Grab a temporary pointer to keep the object alive during our scope.

    if (Comm::IsConnOpen(fwd->serverConnection())) {
        fwd->closeServerConnection("store entry aborted");
    } else {
        debugs(17, 7, HERE << "store entry aborted; no connection to close");
    }
    fwd->stopAndDestroy("store entry aborted");
}

void
FwdState::closeServerConnection(const char *reason)
{
    debugs(17, 3, "because " << reason << "; " << serverConn);
    comm_remove_close_handler(serverConn->fd, closeHandler);
    closeHandler = NULL;
    fwdPconnPool->noteUses(fd_table[serverConn->fd].pconn.uses);
    serverConn->close();
}

/**** PUBLIC INTERFACE ********************************************************/

FwdState::FwdState(const Comm::ConnectionPointer &client, StoreEntry * e, HttpRequest * r, const AccessLogEntryPointer &alp):
    entry(e),
    request(r),
    al(alp),
    err(NULL),
    clientConn(client),
    start_t(squid_curtime),
    n_tries(0),
    destinations(new ResolvedPeers()),
    pconnRace(raceImpossible)
{
    debugs(17, 2, "Forwarding client request " << client << ", url=" << e->url());
    HTTPMSGLOCK(request);
    e->lock("FwdState");
    flags.connected_okay = false;
    flags.dont_retry = false;
    flags.forward_completed = false;
    flags.destinationsFound = false;
    debugs(17, 3, "FwdState constructed, this=" << this);
}

// Called once, right after object creation, when it is safe to set self
void FwdState::start(Pointer aSelf)
{
    // Protect ourselves from being destroyed when the only Server pointing
    // to us is gone (while we expect to talk to more Servers later).
    // Once we set self, we are responsible for clearing it when we do not
    // expect to talk to any servers.
    self = aSelf; // refcounted

    // We hope that either the store entry aborts or peer is selected.
    // Otherwise we are going to leak our object.

    // Ftp::Relay needs to preserve control connection on data aborts
    // so it registers its own abort handler that calls ours when needed.
    if (!request->flags.ftpNative)
        entry->registerAbort(FwdState::abort, this);

    // just in case; should already be initialized to false
    request->flags.pinned = false;

#if STRICT_ORIGINAL_DST
    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we must force DIRECT and only to the original client destination.
    const bool isIntercepted = request && !request->flags.redirected && (request->flags.intercepted || request->flags.interceptTproxy);
    const bool useOriginalDst = Config.onoff.client_dst_passthru || (request && !request->flags.hostVerified);
    if (isIntercepted && useOriginalDst) {
        selectPeerForIntercepted();
        return;
    }
#endif

    // do full route options selection
    startSelectingDestinations(request, al, entry);
}

/// ends forwarding; relies on refcounting so the effect may not be immediate
void
FwdState::stopAndDestroy(const char *reason)
{
    debugs(17, 3, "for " << reason);

    if (opening())
        cancelOpening(reason);

    PeerSelectionInitiator::subscribed = false; // may already be false
    self = nullptr; // we hope refcounting destroys us soon; may already be nil
    /* do not place any code here as this object may be gone by now */
}

/// Notify connOpener that we no longer need connections. We do not have to do
/// this -- connOpener would eventually notice on its own, but notifying reduces
/// waste and speeds up spare connection opening for other transactions (that
/// could otherwise wait for this transaction to use its spare allowance).
void
FwdState::cancelOpening(const char *reason)
{
    assert(calls.connector);
    calls.connector->cancel(reason);
    calls.connector = nullptr;
    notifyConnOpener();
    connOpener.clear();
}

#if STRICT_ORIGINAL_DST
/// bypasses peerSelect() when dealing with intercepted requests
void
FwdState::selectPeerForIntercepted()
{
    // We do not support re-wrapping inside CONNECT.
    // Our only alternative is to fake a noteDestination() call.

    // use pinned connection if available
    if (ConnStateData *client = request->pinnedConnection()) {
        // emulate the PeerSelector::selectPinned() "Skip ICP" effect
        entry->ping_status = PING_DONE;

        usePinned();
        return;
    }

    // use client original destination as second preferred choice
    const auto p = new Comm::Connection();
    p->peerType = ORIGINAL_DST;
    p->remote = clientConn->local;
    getOutgoingAddress(request, p);

    debugs(17, 3, HERE << "using client original destination: " << *p);
    destinations->addPath(p);
    destinations->destinationsFinalized = true;
    PeerSelectionInitiator::subscribed = false;
    useDestinations();
}
#endif

void
FwdState::completed()
{
    if (flags.forward_completed) {
        debugs(17, DBG_IMPORTANT, HERE << "FwdState::completed called on a completed request! Bad!");
        return;
    }

    flags.forward_completed = true;

    request->hier.stopPeerClock(false);

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        debugs(17, 3, HERE << "entry aborted");
        return ;
    }

#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (entry->store_status == STORE_PENDING) {
        if (entry->isEmpty()) {
            if (!err) // we quit (e.g., fd closed) before an error or content
                fail(new ErrorState(ERR_READ_ERROR, Http::scBadGateway, request, al));
            assert(err);
            errorAppendEntry(entry, err);
            err = NULL;
#if USE_OPENSSL
            if (request->flags.sslPeek && request->clientConnectionManager.valid()) {
                CallJobHere1(17, 4, request->clientConnectionManager, ConnStateData,
                             ConnStateData::httpsPeeked, ConnStateData::PinnedIdleContext(Comm::ConnectionPointer(nullptr), request));
            }
#endif
        } else {
            entry->complete();
            entry->releaseRequest();
        }
    }

    if (storePendingNClients(entry) > 0)
        assert(!EBIT_TEST(entry->flags, ENTRY_FWD_HDR_WAIT));

}

FwdState::~FwdState()
{
    debugs(17, 3, "FwdState destructor start");

    if (! flags.forward_completed)
        completed();

    doneWithRetries();

    HTTPMSGUNLOCK(request);

    delete err;

    entry->unregisterAbort();

    entry->unlock("FwdState");

    entry = NULL;

    if (opening())
        cancelOpening("~FwdState");

    if (Comm::IsConnOpen(serverConn))
        closeServerConnection("~FwdState");

    debugs(17, 3, "FwdState destructed, this=" << this);
}

/**
 * This is the entry point for client-side to start forwarding
 * a transaction.  It is a static method that may or may not
 * allocate a FwdState.
 */
void
FwdState::Start(const Comm::ConnectionPointer &clientConn, StoreEntry *entry, HttpRequest *request, const AccessLogEntryPointer &al)
{
    /** \note
     * client_addr == no_addr indicates this is an "internal" request
     * from peer_digest.c, asn.c, netdb.c, etc and should always
     * be allowed.  yuck, I know.
     */

    if ( Config.accessList.miss && !request->client_addr.isNoAddr() &&
            !request->flags.internal && request->url.getScheme() != AnyP::PROTO_CACHE_OBJECT) {
        /**
         * Check if this host is allowed to fetch MISSES from us (miss_access).
         * Intentionally replace the src_addr automatically selected by the checklist code
         * we do NOT want the indirect client address to be tested here.
         */
        ACLFilledChecklist ch(Config.accessList.miss, request, NULL);
        ch.al = al;
        ch.src_addr = request->client_addr;
        ch.syncAle(request, nullptr);
        if (ch.fastCheck().denied()) {
            err_type page_id;
            page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName, 1);

            if (page_id == ERR_NONE)
                page_id = ERR_FORWARDING_DENIED;

            const auto anErr = new ErrorState(page_id, Http::scForbidden, request, al);
            errorAppendEntry(entry, anErr); // frees anErr
            return;
        }
    }

    debugs(17, 3, HERE << "'" << entry->url() << "'");
    /*
     * This seems like an odd place to bind mem_obj and request.
     * Might want to assert that request is NULL at this point
     */
    entry->mem_obj->request = request;
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (shutting_down) {
        /* more yuck */
        const auto anErr = new ErrorState(ERR_SHUTTING_DOWN, Http::scServiceUnavailable, request, al);
        errorAppendEntry(entry, anErr); // frees anErr
        return;
    }

    if (request->flags.internal) {
        debugs(17, 2, "calling internalStart() due to request flag");
        internalStart(clientConn, request, entry, al);
        return;
    }

    switch (request->url.getScheme()) {

    case AnyP::PROTO_CACHE_OBJECT:
        debugs(17, 2, "calling CacheManager due to request scheme " << request->url.getScheme());
        CacheManager::GetInstance()->start(clientConn, request, entry, al);
        return;

    case AnyP::PROTO_URN:
        urnStart(request, entry, al);
        return;

    default:
        FwdState::Pointer fwd = new FwdState(clientConn, entry, request, al);
        fwd->start(fwd);
        return;
    }

    /* NOTREACHED */
}

void
FwdState::fwdStart(const Comm::ConnectionPointer &clientConn, StoreEntry *entry, HttpRequest *request)
{
    // Hides AccessLogEntry.h from code that does not supply ALE anyway.
    Start(clientConn, entry, request, NULL);
}

/// subtracts time_t values, returning zero if smaller exceeds the larger value
/// time_t might be unsigned so we need to be careful when subtracting times...
static inline time_t
diffOrZero(const time_t larger, const time_t smaller)
{
    return (larger > smaller) ? (larger - smaller) : 0;
}

/// time left to finish the whole forwarding process (which started at fwdStart)
time_t
FwdState::ForwardTimeout(const time_t fwdStart)
{
    // time already spent on forwarding (0 if clock went backwards)
    const time_t timeSpent = diffOrZero(squid_curtime, fwdStart);
    return diffOrZero(Config.Timeout.forward, timeSpent);
}

bool
FwdState::EnoughTimeToReForward(const time_t fwdStart)
{
    return ForwardTimeout(fwdStart) > 0;
}

void
FwdState::useDestinations()
{
    if (!destinations->empty()) {
        connectStart();
    } else {
        if (PeerSelectionInitiator::subscribed) {
            debugs(17, 4, "wait for more destinations to try");
            return; // expect a noteDestination*() call
        }

        debugs(17, 3, HERE << "Connection failed: " << entry->url());
        if (!err) {
            const auto anErr = new ErrorState(ERR_CANNOT_FORWARD, Http::scInternalServerError, request, al);
            fail(anErr);
        } // else use actual error from last connection attempt

        stopAndDestroy("tried all destinations");
    }
}

void
FwdState::fail(ErrorState * errorState)
{
    debugs(17, 3, err_type_str[errorState->type] << " \"" << Http::StatusCodeString(errorState->httpStatus) << "\"\n\t" << entry->url());

    delete err;
    err = errorState;

    if (!errorState->request)
        errorState->request = request;

    if (err->type != ERR_ZERO_SIZE_OBJECT)
        return;

    if (pconnRace == racePossible) {
        debugs(17, 5, HERE << "pconn race happened");
        pconnRace = raceHappened;
        destinations->retryPath(serverConn);
    }

    if (ConnStateData *pinned_connection = request->pinnedConnection()) {
        pinned_connection->pinning.zeroReply = true;
        debugs(17, 4, "zero reply on pinned connection");
    }
}

/**
 * Frees fwdState without closing FD or generating an abort
 */
void
FwdState::unregister(Comm::ConnectionPointer &conn)
{
    debugs(17, 3, HERE << entry->url() );
    assert(serverConnection() == conn);
    assert(Comm::IsConnOpen(conn));
    comm_remove_close_handler(conn->fd, closeHandler);
    closeHandler = NULL;
    serverConn = NULL;
}

// \deprecated use unregister(Comm::ConnectionPointer &conn) instead
void
FwdState::unregister(int fd)
{
    debugs(17, 3, HERE << entry->url() );
    assert(fd == serverConnection()->fd);
    unregister(serverConn);
}

/**
 * FooClient modules call fwdComplete() when they are done
 * downloading an object.  Then, we either 1) re-forward the
 * request somewhere else if needed, or 2) call storeComplete()
 * to finish it off
 */
void
FwdState::complete()
{
    const auto replyStatus = entry->mem().baseReply().sline.status();
    debugs(17, 3, *entry << " status " << replyStatus << ' ' << entry->url());
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    logReplyStatus(n_tries, replyStatus);

    if (reforward()) {
        debugs(17, 3, "re-forwarding " << replyStatus << " " << entry->url());

        if (Comm::IsConnOpen(serverConn))
            unregister(serverConn);

        entry->reset();

        useDestinations();

    } else {
        if (Comm::IsConnOpen(serverConn))
            debugs(17, 3, "server FD " << serverConnection()->fd << " not re-forwarding status " << replyStatus);
        else
            debugs(17, 3, "server (FD closed) not re-forwarding status " << replyStatus);
        entry->complete();

        if (!Comm::IsConnOpen(serverConn))
            completed();

        stopAndDestroy("forwarding completed");
    }
}

void
FwdState::noteDestination(Comm::ConnectionPointer path)
{
    flags.destinationsFound = true;

    if (!path) {
        // We can call usePinned() without fear of clashing with an earlier
        // forwarding attempt because PINNED must be the first destination.
        assert(destinations->empty());
        usePinned();
        return;
    }

    debugs(17, 3, path);

    destinations->addPath(path);

    if (Comm::IsConnOpen(serverConn)) {
        // We are already using a previously opened connection, so we cannot be
        // waiting for connOpener. We still receive destinations for backup.
        Must(!opening());
        return;
    }

    if (opening()) {
        notifyConnOpener();
        return; // and continue to wait for FwdState::noteConnection() callback
    }

    // This is the first path candidate we have seen. Create connOpener.
    useDestinations();
}

void
FwdState::noteDestinationsEnd(ErrorState *selectionError)
{
    PeerSelectionInitiator::subscribed = false;
    destinations->destinationsFinalized = true;

    if (!flags.destinationsFound) {
        if (selectionError) {
            debugs(17, 3, "Will abort forwarding because path selection has failed.");
            Must(!err); // if we tried to connect, then path selection succeeded
            fail(selectionError);
        }
        else if (err)
            debugs(17, 3, "Will abort forwarding because all found paths have failed.");
        else
            debugs(17, 3, "Will abort forwarding because path selection found no paths.");

        useDestinations(); // will detect and handle the lack of paths
        return;
    }
    // else continue to use one of the previously noted destinations;
    // if all of them fail, forwarding as whole will fail
    Must(!selectionError); // finding at least one path means selection succeeded

    if (Comm::IsConnOpen(serverConn)) {
        // We are already using a previously opened connection, so we cannot be
        // waiting for connOpener. We were receiving destinations for backup.
        Must(!opening());
        return;
    }

    Must(opening()); // or we would be stuck with nothing to do or wait for
    notifyConnOpener();
    // and continue to wait for FwdState::noteConnection() callback
}

/// makes sure connOpener knows that destinations have changed
void
FwdState::notifyConnOpener()
{
    if (destinations->notificationPending) {
        debugs(17, 7, "reusing pending notification about " << *destinations);
    } else {
        debugs(17, 7, "notifying about " << *destinations);
        destinations->notificationPending = true;
        CallJobHere(17, 5, connOpener, HappyConnOpener, noteCandidatesChange);
    }
}

/**** CALLBACK WRAPPERS ************************************************************/

static void
fwdServerClosedWrapper(const CommCloseCbParams &params)
{
    FwdState *fwd = (FwdState *)params.data;
    fwd->serverClosed(params.fd);
}

/**** PRIVATE *****************************************************************/

/*
 * FwdState::checkRetry
 *
 * Return TRUE if the request SHOULD be retried.  This method is
 * called when the HTTP connection fails, or when the connection
 * is closed before reading the end of HTTP headers from the server.
 */
bool
FwdState::checkRetry()
{
    if (shutting_down)
        return false;

    if (!self) { // we have aborted before the server called us back
        debugs(17, 5, HERE << "not retrying because of earlier abort");
        // we will be destroyed when the server clears its Pointer to us
        return false;
    }

    if (entry->store_status != STORE_PENDING)
        return false;

    if (!entry->isEmpty())
        return false;

    if (exhaustedTries())
        return false;

    if (request->flags.pinned && !pinnedCanRetry())
        return false;

    if (!EnoughTimeToReForward(start_t))
        return false;

    if (flags.dont_retry)
        return false;

    if (request->bodyNibbled())
        return false;

    // NP: not yet actually connected anywhere. retry is safe.
    if (!flags.connected_okay)
        return true;

    if (!checkRetriable())
        return false;

    return true;
}

/// Whether we may try sending this request again after a failure.
bool
FwdState::checkRetriable()
{
    // Optimize: A compliant proxy may retry PUTs, but Squid lacks the [rather
    // complicated] code required to protect the PUT request body from being
    // nibbled during the first try. Thus, Squid cannot retry some PUTs today.
    if (request->body_pipe != NULL)
        return false;

    // RFC2616 9.1 Safe and Idempotent Methods
    return (request->method.isHttpSafe() || request->method.isIdempotent());
}

void
FwdState::serverClosed(int fd)
{
    // XXX: fd is often -1 here
    debugs(17, 2, "FD " << fd << " " << entry->url() << " after " <<
           (fd >= 0 ? fd_table[fd].pconn.uses : -1) << " requests");
    if (fd >= 0 && serverConnection()->fd == fd)
        fwdPconnPool->noteUses(fd_table[fd].pconn.uses);
    retryOrBail();
}

void
FwdState::retryOrBail()
{
    if (checkRetry()) {
        debugs(17, 3, HERE << "re-forwarding (" << n_tries << " tries, " << (squid_curtime - start_t) << " secs)");
        useDestinations();
        return;
    }

    // TODO: should we call completed() here and move doneWithRetries there?
    doneWithRetries();

    request->hier.stopPeerClock(false);

    if (self != NULL && !err && shutting_down && entry->isEmpty()) {
        const auto anErr = new ErrorState(ERR_SHUTTING_DOWN, Http::scServiceUnavailable, request, al);
        errorAppendEntry(entry, anErr);
    }

    stopAndDestroy("cannot retry");
}

// If the Server quits before nibbling at the request body, the body sender
// will not know (so that we can retry). Call this if we will not retry. We
// will notify the sender so that it does not get stuck waiting for space.
void
FwdState::doneWithRetries()
{
    if (request && request->body_pipe != NULL)
        request->body_pipe->expectNoConsumption();
}

// called by the server that failed after calling unregister()
void
FwdState::handleUnregisteredServerEnd()
{
    debugs(17, 2, HERE << "self=" << self << " err=" << err << ' ' << entry->url());
    assert(!Comm::IsConnOpen(serverConn));
    retryOrBail();
}

/// called when a to-peer connection has been successfully obtained or
/// when all candidate destinations have been tried and all have failed
void
FwdState::noteConnection(HappyConnOpener::Answer &answer)
{
    calls.connector = nullptr;
    connOpener.clear();

    Must(n_tries <= answer.n_tries); // n_tries cannot decrease
    n_tries = answer.n_tries;

    if (const auto error = answer.error.get()) {
        flags.dont_retry = true; // or HappyConnOpener would not have given up
        syncHierNote(answer.conn, request->url.host());
        fail(error);
        answer.error.clear(); // preserve error for errorSendComplete()
        retryOrBail(); // will notice flags.dont_retry and bail
        return;
    }

    syncWithServerConn(answer.conn, request->url.host(), answer.reused);

    if (answer.reused)
        return dispatch();

    // Check if we need to TLS before use
    if (const CachePeer *peer = serverConnection()->getPeer()) {
        // Assume that it is only possible for the client-first from the
        // bumping modes to try connect to a remote server. The bumped
        // requests with other modes are using pinned connections or fails.
        const bool clientFirstBump = request->flags.sslBumped;
        // We need a CONNECT tunnel to send encrypted traffic through a proxy,
        // but we do not support TLS inside TLS, so we exclude HTTPS proxies.
        const bool originWantsEncryptedTraffic =
            request->method == Http::METHOD_CONNECT ||
            request->flags.sslPeek ||
            clientFirstBump;
        if (originWantsEncryptedTraffic && // the "encrypted traffic" part
                !peer->options.originserver && // the "through a proxy" part
                !peer->secure.encryptTransport) // the "exclude HTTPS proxies" part
            return establishTunnelThruProxy();
    }

    secureConnectionToPeerIfNeeded();
}

void
FwdState::establishTunnelThruProxy()
{
    AsyncCall::Pointer callback = asyncCall(17,4,
                                            "FwdState::tunnelEstablishmentDone",
                                            Http::Tunneler::CbDialer<FwdState>(&FwdState::tunnelEstablishmentDone, this));
    HttpRequest::Pointer requestPointer = request;
    const auto tunneler = new Http::Tunneler(serverConnection(), requestPointer, callback, connectingTimeout(serverConnection()), al);
#if USE_DELAY_POOLS
    Must(serverConnection()->getPeer());
    if (!serverConnection()->getPeer()->options.no_delay)
        tunneler->setDelayId(entry->mem_obj->mostBytesAllowed());
#endif
    AsyncJob::Start(tunneler);
    // and wait for the tunnelEstablishmentDone() call
}

/// resumes operations after the (possibly failed) HTTP CONNECT exchange
void
FwdState::tunnelEstablishmentDone(Http::TunnelerAnswer &answer)
{
    if (answer.positive()) {
        if (answer.leftovers.isEmpty()) {
            secureConnectionToPeerIfNeeded();
            return;
        }
        // This should not happen because TLS servers do not speak first. If we
        // have to handle this, then pass answer.leftovers via a PeerConnector
        // to ServerBio. See ClientBio::setReadBufData().
        static int occurrences = 0;
        const auto level = (occurrences++ < 100) ? DBG_IMPORTANT : 2;
        debugs(17, level, "ERROR: Early data after CONNECT response. " <<
               "Found " << answer.leftovers.length() << " bytes. " <<
               "Closing " << serverConnection());
        fail(new ErrorState(ERR_CONNECT_FAIL, Http::scBadGateway, request, al));
        closeServerConnection("found early data after CONNECT response");
        retryOrBail();
        return;
    }

    // TODO: Reuse to-peer connections after a CONNECT error response.

    if (const auto peer = serverConnection()->getPeer())
        peerConnectFailed(peer);

    const auto error = answer.squidError.get();
    Must(error);
    answer.squidError.clear(); // preserve error for fail()
    fail(error);
    closeServerConnection("Squid-generated CONNECT error");
    retryOrBail();
}

/// handles an established TCP connection to peer (including origin servers)
void
FwdState::secureConnectionToPeerIfNeeded()
{
    assert(!request->flags.pinned);

    const CachePeer *p = serverConnection()->getPeer();
    const bool peerWantsTls = p && p->secure.encryptTransport;
    // userWillTlsToPeerForUs assumes CONNECT == HTTPS
    const bool userWillTlsToPeerForUs = p && p->options.originserver &&
                                        request->method == Http::METHOD_CONNECT;
    const bool needTlsToPeer = peerWantsTls && !userWillTlsToPeerForUs;
    const bool clientFirstBump = request->flags.sslBumped; // client-first (already) bumped connection
    const bool needsBump = request->flags.sslPeek || clientFirstBump;

    // 'GET https://...' requests. If a peer is used the request is forwarded
    // as is
    const bool needTlsToOrigin = !p && request->url.getScheme() == AnyP::PROTO_HTTPS && !clientFirstBump;

    if (needTlsToPeer || needTlsToOrigin || needsBump) {
        HttpRequest::Pointer requestPointer = request;
        AsyncCall::Pointer callback = asyncCall(17,4,
                                                "FwdState::ConnectedToPeer",
                                                FwdStatePeerAnswerDialer(&FwdState::connectedToPeer, this));
        const auto sslNegotiationTimeout = connectingTimeout(serverConnection());
        Security::PeerConnector *connector = nullptr;
#if USE_OPENSSL
        if (request->flags.sslPeek)
            connector = new Ssl::PeekingPeerConnector(requestPointer, serverConnection(), clientConn, callback, al, sslNegotiationTimeout);
        else
#endif
            connector = new Security::BlindPeerConnector(requestPointer, serverConnection(), callback, al, sslNegotiationTimeout);
        AsyncJob::Start(connector); // will call our callback
        return;
    }

    // if not encrypting just run the post-connect actions
    successfullyConnectedToPeer();
}

/// called when all negotiations with the TLS-speaking peer have been completed
void
FwdState::connectedToPeer(Security::EncryptorAnswer &answer)
{
    if (ErrorState *error = answer.error.get()) {
        fail(error);
        answer.error.clear(); // preserve error for errorSendComplete()
        if (CachePeer *p = serverConnection()->getPeer())
            peerConnectFailed(p);
        serverConnection()->close();
        return;
    }

    if (answer.tunneled) {
        // TODO: When ConnStateData establishes tunnels, its state changes
        // [in ways that may affect logging?]. Consider informing
        // ConnStateData about our tunnel or otherwise unifying tunnel
        // establishment [side effects].
        unregister(serverConn); // async call owns it now
        complete(); // destroys us
        return;
    }

    successfullyConnectedToPeer();
}

/// called when all negotiations with the peer have been completed
void
FwdState::successfullyConnectedToPeer()
{
    // should reach ConnStateData before the dispatched Client job starts
    CallJobHere1(17, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::notePeerConnection, serverConnection());

    if (serverConnection()->getPeer())
        peerConnectSucceded(serverConnection()->getPeer());

    dispatch();
}

/// commits to using the given open to-peer connection
void
FwdState::syncWithServerConn(const Comm::ConnectionPointer &conn, const char *host, const bool reused)
{
    Must(IsConnOpen(conn));
    serverConn = conn;

    closeHandler = comm_add_close_handler(serverConn->fd,  fwdServerClosedWrapper, this);

    if (reused) {
        pconnRace = racePossible;
        ResetMarkingsToServer(request, *serverConn);
    } else {
        pconnRace = raceImpossible;
        // Comm::ConnOpener already applied proper/current markings
    }

    syncHierNote(serverConn, host);
}

void
FwdState::syncHierNote(const Comm::ConnectionPointer &server, const char *host)
{
    if (request)
        request->hier.resetPeerNotes(server, host);
    if (al)
        al->hier.resetPeerNotes(server, host);
}

/**
 * Called after forwarding path selection (via peer select) has taken place
 * and whenever forwarding needs to attempt a new connection (routing failover).
 * We have a vector of possible localIP->remoteIP paths now ready to start being connected.
 */
void
FwdState::connectStart()
{
    debugs(17, 3, *destinations << " to " << entry->url());

    Must(!request->pinnedConnection());

    assert(!destinations->empty());
    assert(!opening());

    // Ditch error page if it was created before.
    // A new one will be created if there's another problem
    delete err;
    err = nullptr;
    request->clearError();
    serverConn = nullptr;

    request->hier.startPeerClock();

    calls.connector = asyncCall(17, 5, "FwdState::noteConnection", HappyConnOpener::CbDialer<FwdState>(&FwdState::noteConnection, this));

    HttpRequest::Pointer cause = request;
    const auto cs = new HappyConnOpener(destinations, calls.connector, cause, start_t, n_tries, al);
    cs->setHost(request->url.host());
    bool retriable = checkRetriable();
    if (!retriable && Config.accessList.serverPconnForNonretriable) {
        ACLFilledChecklist ch(Config.accessList.serverPconnForNonretriable, request, nullptr);
        ch.al = al;
        ch.syncAle(request, nullptr);
        retriable = ch.fastCheck().allowed();
    }
    cs->setRetriable(retriable);
    cs->allowPersistent(pconnRace != raceHappened);
    destinations->notificationPending = true; // start() is async
    connOpener = cs;
    AsyncJob::Start(cs);
}

/// send request on an existing connection dedicated to the requesting client
void
FwdState::usePinned()
{
    const auto connManager = request->pinnedConnection();
    debugs(17, 7, "connection manager: " << connManager);

    try {
        serverConn = ConnStateData::BorrowPinnedConnection(request, al);
        debugs(17, 5, "connection: " << serverConn);
    } catch (ErrorState * const anErr) {
        syncHierNote(nullptr, connManager ? connManager->pinning.host : request->url.host());
        serverConn = nullptr;
        fail(anErr);
        // Connection managers monitor their idle pinned to-server
        // connections and close from-client connections upon seeing
        // a to-server connection closure. Retrying here is futile.
        stopAndDestroy("pinned connection failure");
        return;
    }

    ++n_tries;
    request->flags.pinned = true;

    assert(connManager);
    if (connManager->pinnedAuth())
        request->flags.auth = true;

    // the server may close the pinned connection before this request
    const auto reused = true;
    syncWithServerConn(serverConn, connManager->pinning.host, reused);

    dispatch();
}

void
FwdState::dispatch()
{
    debugs(17, 3, clientConn << ": Fetching " << request->method << ' ' << entry->url());
    /*
     * Assert that server_fd is set.  This is to guarantee that fwdState
     * is attached to something and will be deallocated when server_fd
     * is closed.
     */
    assert(Comm::IsConnOpen(serverConn));

    fd_note(serverConnection()->fd, entry->url());

    fd_table[serverConnection()->fd].noteUse();

    /*assert(!EBIT_TEST(entry->flags, ENTRY_DISPATCHED)); */
    assert(entry->ping_status != PING_WAITING);

    assert(entry->locked());

    EBIT_SET(entry->flags, ENTRY_DISPATCHED);

    flags.connected_okay = true;

    netdbPingSite(request->url.host());

    /* Retrieves remote server TOS or MARK value, and stores it as part of the
     * original client request FD object. It is later used to forward
     * remote server's TOS/MARK in the response to the client in case of a MISS.
     */
    if (Ip::Qos::TheConfig.isHitNfmarkActive()) {
        if (Comm::IsConnOpen(clientConn) && Comm::IsConnOpen(serverConnection())) {
            fde * clientFde = &fd_table[clientConn->fd]; // XXX: move the fd_table access into Ip::Qos
            /* Get the netfilter CONNMARK */
            clientFde->nfConnmarkFromServer = Ip::Qos::getNfConnmark(serverConnection(), Ip::Qos::dirOpened);
        }
    }

#if _SQUID_LINUX_
    /* Bug 2537: The TOS forward part of QOS only applies to patched Linux kernels. */
    if (Ip::Qos::TheConfig.isHitTosActive()) {
        if (Comm::IsConnOpen(clientConn)) {
            fde * clientFde = &fd_table[clientConn->fd]; // XXX: move the fd_table access into Ip::Qos
            /* Get the TOS value for the packet */
            Ip::Qos::getTosFromServer(serverConnection(), clientFde);
        }
    }
#endif

#if USE_OPENSSL
    if (request->flags.sslPeek) {
        CallJobHere1(17, 4, request->clientConnectionManager, ConnStateData,
                     ConnStateData::httpsPeeked, ConnStateData::PinnedIdleContext(serverConnection(), request));
        unregister(serverConn); // async call owns it now
        complete(); // destroys us
        return;
    }
#endif

    if (const auto peer = serverConnection()->getPeer()) {
        ++peer->stats.fetches;
        request->prepForPeering(*peer);
        httpStart(this);
    } else {
        assert(!request->flags.sslPeek);
        request->prepForDirect();

        switch (request->url.getScheme()) {

        case AnyP::PROTO_HTTPS:
            httpStart(this);
            break;

        case AnyP::PROTO_HTTP:
            httpStart(this);
            break;

        case AnyP::PROTO_GOPHER:
            gopherStart(this);
            break;

        case AnyP::PROTO_FTP:
            if (request->flags.ftpNative)
                Ftp::StartRelay(this);
            else
                Ftp::StartGateway(this);
            break;

        case AnyP::PROTO_CACHE_OBJECT:

        case AnyP::PROTO_URN:
            fatal_dump("Should never get here");
            break;

        case AnyP::PROTO_WHOIS:
            whoisStart(this);
            break;

        case AnyP::PROTO_WAIS:  /* Not implemented */

        default:
            debugs(17, DBG_IMPORTANT, "WARNING: Cannot retrieve '" << entry->url() << "'.");
            const auto anErr = new ErrorState(ERR_UNSUP_REQ, Http::scBadRequest, request, al);
            fail(anErr);
            // Set the dont_retry flag because this is not a transient (network) error.
            flags.dont_retry = true;
            if (Comm::IsConnOpen(serverConn)) {
                serverConn->close();
            }
            break;
        }
    }
}

/*
 * FwdState::reforward
 *
 * returns TRUE if the transaction SHOULD be re-forwarded to the
 * next choice in the serverDestinations list.  This method is called when
 * peer communication completes normally, or experiences
 * some error after receiving the end of HTTP headers.
 */
int
FwdState::reforward()
{
    StoreEntry *e = entry;

    if (EBIT_TEST(e->flags, ENTRY_ABORTED)) {
        debugs(17, 3, HERE << "entry aborted");
        return 0;
    }

    assert(e->store_status == STORE_PENDING);
    assert(e->mem_obj);
#if URL_CHECKSUM_DEBUG

    e->mem_obj->checkUrlChecksum();
#endif

    debugs(17, 3, HERE << e->url() << "?" );

    if (request->flags.pinned && !pinnedCanRetry()) {
        debugs(17, 3, "pinned connection; cannot retry");
        return 0;
    }

    if (!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
        debugs(17, 3, HERE << "No, ENTRY_FWD_HDR_WAIT isn't set");
        return 0;
    }

    if (exhaustedTries())
        return 0;

    if (request->bodyNibbled())
        return 0;

    if (destinations->empty() && !PeerSelectionInitiator::subscribed) {
        debugs(17, 3, HERE << "No alternative forwarding paths left");
        return 0;
    }

    const auto s = entry->mem().baseReply().sline.status();
    debugs(17, 3, HERE << "status " << s);
    return reforwardableStatus(s);
}

static void
fwdStats(StoreEntry * s)
{
    int i;
    int j;
    storeAppendPrintf(s, "Status");

    for (j = 1; j < MAX_FWD_STATS_IDX; ++j) {
        storeAppendPrintf(s, "\ttry#%d", j);
    }

    storeAppendPrintf(s, "\n");

    for (i = 0; i <= (int) Http::scInvalidHeader; ++i) {
        if (FwdReplyCodes[0][i] == 0)
            continue;

        storeAppendPrintf(s, "%3d", i);

        for (j = 0; j <= MAX_FWD_STATS_IDX; ++j) {
            storeAppendPrintf(s, "\t%d", FwdReplyCodes[j][i]);
        }

        storeAppendPrintf(s, "\n");
    }
}

/**** STATIC MEMBER FUNCTIONS *************************************************/

bool
FwdState::reforwardableStatus(const Http::StatusCode s) const
{
    switch (s) {

    case Http::scBadGateway:

    case Http::scGatewayTimeout:
        return true;

    case Http::scForbidden:

    case Http::scInternalServerError:

    case Http::scNotImplemented:

    case Http::scServiceUnavailable:
        return Config.retry.onerror;

    default:
        return false;
    }

    /* NOTREACHED */
}

void
FwdState::initModule()
{
    RegisterWithCacheManager();
}

void
FwdState::RegisterWithCacheManager(void)
{
    Mgr::RegisterAction("forward", "Request Forwarding Statistics", fwdStats, 0, 1);
}

void
FwdState::logReplyStatus(int tries, const Http::StatusCode status)
{
    if (status > Http::scInvalidHeader)
        return;

    assert(tries >= 0);

    if (tries > MAX_FWD_STATS_IDX)
        tries = MAX_FWD_STATS_IDX;

    ++ FwdReplyCodes[tries][status];
}

bool
FwdState::exhaustedTries() const
{
    return n_tries >= Config.forward_max_tries;
}

bool
FwdState::pinnedCanRetry() const
{
    assert(request->flags.pinned);

    // pconn race on pinned connection: Currently we do not have any mechanism
    // to retry current pinned connection path.
    if (pconnRace == raceHappened)
        return false;

    // If a bumped connection was pinned, then the TLS client was given our peer
    // details. Do not retry because we do not ensure that those details stay
    // constant. Step1-bumped connections do not get our TLS peer details, are
    // never pinned, and, hence, never reach this method.
    if (request->flags.sslBumped)
        return false;

    // The other pinned cases are FTP proxying and connection-based HTTP
    // authentication. TODO: Do these cases have restrictions?
    return true;
}

time_t
FwdState::connectingTimeout(const Comm::ConnectionPointer &conn) const
{
    const auto connTimeout = conn->connectTimeout(start_t);
    return positiveTimeout(connTimeout);
}

/**** PRIVATE NON-MEMBER FUNCTIONS ********************************************/

/*
 * DPW 2007-05-19
 * Formerly static, but now used by client_side_request.cc
 */
/// Checks for a TOS value to apply depending on the ACL
tos_t
aclMapTOS(acl_tos * head, ACLChecklist * ch)
{
    for (acl_tos *l = head; l; l = l->next) {
        if (!l->aclList || ch->fastCheck(l->aclList).allowed())
            return l->tos;
    }

    return 0;
}

/// Checks for a netfilter mark value to apply depending on the ACL
Ip::NfMarkConfig
aclFindNfMarkConfig(acl_nfmark * head, ACLChecklist * ch)
{
    for (acl_nfmark *l = head; l; l = l->next) {
        if (!l->aclList || ch->fastCheck(l->aclList).allowed())
            return l->markConfig;
    }

    return {};
}

void
getOutgoingAddress(HttpRequest * request, const Comm::ConnectionPointer &conn)
{
    // skip if an outgoing address is already set.
    if (!conn->local.isAnyAddr()) return;

    // ensure that at minimum the wildcard local matches remote protocol
    if (conn->remote.isIPv4())
        conn->local.setIPv4();

    // maybe use TPROXY client address
    if (request && request->flags.spoofClientIp) {
        if (!conn->getPeer() || !conn->getPeer()->options.no_tproxy) {
#if FOLLOW_X_FORWARDED_FOR && LINUX_NETFILTER
            if (Config.onoff.tproxy_uses_indirect_client)
                conn->local = request->indirect_client_addr;
            else
#endif
                conn->local = request->client_addr;
            conn->local.port(0); // let OS pick the source port to prevent address clashes
            // some flags need setting on the socket to use this address
            conn->flags |= COMM_DOBIND;
            conn->flags |= COMM_TRANSPARENT;
            return;
        }
        // else no tproxy today ...
    }

    if (!Config.accessList.outgoing_address) {
        return; // anything will do.
    }

    ACLFilledChecklist ch(NULL, request, NULL);
    ch.dst_peer_name = conn->getPeer() ? conn->getPeer()->name : NULL;
    ch.dst_addr = conn->remote;

    // TODO use the connection details in ACL.
    // needs a bit of rework in ACLFilledChecklist to use Comm::Connection instead of ConnStateData

    for (Acl::Address *l = Config.accessList.outgoing_address; l; l = l->next) {

        /* check if the outgoing address is usable to the destination */
        if (conn->remote.isIPv4() != l->addr.isIPv4()) continue;

        /* check ACLs for this outgoing address */
        if (!l->aclList || ch.fastCheck(l->aclList).allowed()) {
            conn->local = l->addr;
            return;
        }
    }
}

/// \returns the TOS value that should be set on the to-peer connection
static tos_t
GetTosToServer(HttpRequest * request, Comm::Connection &conn)
{
    if (!Ip::Qos::TheConfig.tosToServer)
        return 0;

    ACLFilledChecklist ch(NULL, request, NULL);
    ch.dst_peer_name = conn.getPeer() ? conn.getPeer()->name : nullptr;
    ch.dst_addr = conn.remote;
    return aclMapTOS(Ip::Qos::TheConfig.tosToServer, &ch);
}

/// \returns the Netfilter mark that should be set on the to-peer connection
static nfmark_t
GetNfmarkToServer(HttpRequest * request, Comm::Connection &conn)
{
    if (!Ip::Qos::TheConfig.nfmarkToServer)
        return 0;

    ACLFilledChecklist ch(NULL, request, NULL);
    ch.dst_peer_name = conn.getPeer() ? conn.getPeer()->name : nullptr;
    ch.dst_addr = conn.remote;
    const auto mc = aclFindNfMarkConfig(Ip::Qos::TheConfig.nfmarkToServer, &ch);
    return mc.mark;
}

void
GetMarkingsToServer(HttpRequest * request, Comm::Connection &conn)
{
    // Get the server side TOS and Netfilter mark to be set on the connection.
    conn.tos = GetTosToServer(request, conn);
    conn.nfmark = GetNfmarkToServer(request, conn);
    debugs(17, 3, "from " << conn.local << " tos " << int(conn.tos) << " netfilter mark " << conn.nfmark);
}

void
ResetMarkingsToServer(HttpRequest * request, Comm::Connection &conn)
{
    GetMarkingsToServer(request, conn);

    // TODO: Avoid these calls if markings has not changed.
    if (conn.tos)
        Ip::Qos::setSockTos(&conn, conn.tos);
    if (conn.nfmark)
        Ip::Qos::setSockNfmark(&conn, conn.nfmark);
}

