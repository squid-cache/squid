/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
#include "hier_code.h"
#include "http.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "internal.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "PeerSelectState.h"
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

static PSC fwdPeerSelectionCompleteWrapper;
static CLCB fwdServerClosedWrapper;
static CNCB fwdConnectDoneWrapper;

static OBJH fwdStats;

#define MAX_FWD_STATS_IDX 9
static int FwdReplyCodes[MAX_FWD_STATS_IDX + 1][Http::scInvalidHeader + 1];

static PconnPool *fwdPconnPool = new PconnPool("server-peers", NULL);
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
    fwd->serverDestinations.clear();
    fwd->self = NULL;
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
    pconnRace(raceImpossible)
{
    debugs(17, 2, "Forwarding client request " << client << ", url=" << e->url());
    HTTPMSGLOCK(request);
    serverDestinations.reserve(Config.forward_max_tries);
    e->lock("FwdState");
    EBIT_SET(e->flags, ENTRY_FWD_HDR_WAIT);
    flags.connected_okay = false;
    flags.dont_retry = false;
    flags.forward_completed = false;
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

#if STRICT_ORIGINAL_DST
    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we must force DIRECT and only to the original client destination.
    const bool isIntercepted = request && !request->flags.redirected && (request->flags.intercepted || request->flags.interceptTproxy);
    const bool useOriginalDst = Config.onoff.client_dst_passthru || (request && !request->flags.hostVerified);
    if (isIntercepted && useOriginalDst) {
        selectPeerForIntercepted();
        // 3.2 does not suppro re-wrapping inside CONNECT.
        // our only alternative is to fake destination "found" and continue with the forwarding.
        startConnectionOrFail();
        return;
    }
#endif

    // do full route options selection
    peerSelect(&serverDestinations, request, al, entry, fwdPeerSelectionCompleteWrapper, this);
}

#if STRICT_ORIGINAL_DST
/// bypasses peerSelect() when dealing with intercepted requests
void
FwdState::selectPeerForIntercepted()
{
    // use pinned connection if available
    Comm::ConnectionPointer p;
    if (ConnStateData *client = request->pinnedConnection()) {
        p = client->validatePinnedConnection(request, NULL);
        if (Comm::IsConnOpen(p)) {
            /* duplicate peerSelectPinned() effects */
            p->peerType = PINNED;
            entry->ping_status = PING_DONE;     /* Skip ICP */

            debugs(17, 3, "reusing a pinned conn: " << *p);
            serverDestinations.push_back(p);
        } else {
            debugs(17,2, "Pinned connection is not valid: " << p);
            ErrorState *anErr = new ErrorState(ERR_ZERO_SIZE_OBJECT, Http::scServiceUnavailable, request);
            fail(anErr);
        }
        // Either use the valid pinned connection or fail if it is invalid.
        return;
    }

    // use client original destination as second preferred choice
    p = new Comm::Connection();
    p->peerType = ORIGINAL_DST;
    p->remote = clientConn->local;
    getOutgoingAddress(request, p);

    debugs(17, 3, HERE << "using client original destination: " << *p);
    serverDestinations.push_back(p);
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
                fail(new ErrorState(ERR_READ_ERROR, Http::scBadGateway, request));
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
            EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
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

    if (calls.connector != NULL) {
        calls.connector->cancel("FwdState destructed");
        calls.connector = NULL;
    }

    if (Comm::IsConnOpen(serverConn))
        closeServerConnection("~FwdState");

    serverDestinations.clear();

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
        ch.src_addr = request->client_addr;
        if (ch.fastCheck().denied()) {
            err_type page_id;
            page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName, 1);

            if (page_id == ERR_NONE)
                page_id = ERR_FORWARDING_DENIED;

            ErrorState *anErr = new ErrorState(page_id, Http::scForbidden, request);
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
    HTTPMSGLOCK(entry->mem_obj->request);
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (shutting_down) {
        /* more yuck */
        ErrorState *anErr = new ErrorState(ERR_SHUTTING_DOWN, Http::scServiceUnavailable, request);
        errorAppendEntry(entry, anErr); // frees anErr
        return;
    }

    if (request->flags.internal) {
        debugs(17, 2, "calling internalStart() due to request flag");
        internalStart(clientConn, request, entry);
        return;
    }

    switch (request->url.getScheme()) {

    case AnyP::PROTO_CACHE_OBJECT:
        debugs(17, 2, "calling CacheManager due to request scheme " << request->url.getScheme());
        CacheManager::GetInstance()->Start(clientConn, request, entry);
        return;

    case AnyP::PROTO_URN:
        urnStart(request, entry);
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
FwdState::startConnectionOrFail()
{
    debugs(17, 3, HERE << entry->url());

    if (serverDestinations.size() > 0) {
        // Ditch error page if it was created before.
        // A new one will be created if there's another problem
        delete err;
        err = NULL;

        // Update the logging information about this new server connection.
        // Done here before anything else so the errors get logged for
        // this server link regardless of what happens when connecting to it.
        // IF sucessfuly connected this top destination will become the serverConnection().
        syncHierNote(serverDestinations[0], request->url.host());
        request->clearError();

        connectStart();
    } else {
        debugs(17, 3, HERE << "Connection failed: " << entry->url());
        if (!err) {
            ErrorState *anErr = new ErrorState(ERR_CANNOT_FORWARD, Http::scInternalServerError, request);
            fail(anErr);
        } // else use actual error from last connection attempt
        self = NULL;       // refcounted
    }
}

void
FwdState::fail(ErrorState * errorState)
{
    debugs(17, 3, err_type_str[errorState->type] << " \"" << Http::StatusCodeString(errorState->httpStatus) << "\"\n\t" << entry->url());

    delete err;
    err = errorState;

    if (!errorState->request) {
        errorState->request = request;
        HTTPMSGLOCK(errorState->request);
    }

    if (err->type != ERR_ZERO_SIZE_OBJECT)
        return;

    if (pconnRace == racePossible) {
        debugs(17, 5, HERE << "pconn race happened");
        pconnRace = raceHappened;
    }

    if (ConnStateData *pinned_connection = request->pinnedConnection()) {
        pinned_connection->pinning.zeroReply = true;
        flags.dont_retry = true; // we want to propagate failure to the client
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
    debugs(17, 3, HERE << entry->url() << "\n\tstatus " << entry->getReply()->sline.status());
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    logReplyStatus(n_tries, entry->getReply()->sline.status());

    if (reforward()) {
        debugs(17, 3, HERE << "re-forwarding " << entry->getReply()->sline.status() << " " << entry->url());

        if (Comm::IsConnOpen(serverConn))
            unregister(serverConn);

        entry->reset();

        // drop the last path off the selection list. try the next one.
        serverDestinations.erase(serverDestinations.begin());
        startConnectionOrFail();

    } else {
        if (Comm::IsConnOpen(serverConn))
            debugs(17, 3, HERE << "server FD " << serverConnection()->fd << " not re-forwarding status " << entry->getReply()->sline.status());
        else
            debugs(17, 3, HERE << "server (FD closed) not re-forwarding status " << entry->getReply()->sline.status());
        EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
        entry->complete();

        if (!Comm::IsConnOpen(serverConn))
            completed();

        self = NULL; // refcounted
    }
}

/**** CALLBACK WRAPPERS ************************************************************/

static void
fwdPeerSelectionCompleteWrapper(Comm::ConnectionList *, ErrorState *err, void *data)
{
    FwdState *fwd = (FwdState *) data;
    if (err)
        fwd->fail(err);
    fwd->startConnectionOrFail();
}

static void
fwdServerClosedWrapper(const CommCloseCbParams &params)
{
    FwdState *fwd = (FwdState *)params.data;
    fwd->serverClosed(params.fd);
}

void
fwdConnectDoneWrapper(const Comm::ConnectionPointer &conn, Comm::Flag status, int xerrno, void *data)
{
    FwdState *fwd = (FwdState *) data;
    fwd->connectDone(conn, status, xerrno);
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

    if (n_tries > Config.forward_max_tries)
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
        // we should retry the same destination if it failed due to pconn race
        if (pconnRace == raceHappened)
            debugs(17, 4, HERE << "retrying the same destination");
        else
            serverDestinations.erase(serverDestinations.begin()); // last one failed. try another.
        startConnectionOrFail();
        return;
    }

    // TODO: should we call completed() here and move doneWithRetries there?
    doneWithRetries();

    request->hier.stopPeerClock(false);

    if (self != NULL && !err && shutting_down && entry->isEmpty()) {
        ErrorState *anErr = new ErrorState(ERR_SHUTTING_DOWN, Http::scServiceUnavailable, request);
        errorAppendEntry(entry, anErr);
    }

    self = NULL;    // refcounted
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

void
FwdState::connectDone(const Comm::ConnectionPointer &conn, Comm::Flag status, int xerrno)
{
    if (status != Comm::OK) {
        ErrorState *const anErr = makeConnectingError(ERR_CONNECT_FAIL);
        anErr->xerrno = xerrno;
        fail(anErr);

        /* it might have been a timeout with a partially open link */
        if (conn != NULL) {
            if (conn->getPeer())
                peerConnectFailed(conn->getPeer());

            conn->close();
        }
        retryOrBail();
        return;
    }

    serverConn = conn;
    debugs(17, 3, HERE << serverConnection() << ": '" << entry->url() << "'" );

    closeHandler = comm_add_close_handler(serverConnection()->fd, fwdServerClosedWrapper, this);

    if (!request->flags.pinned) {
        const CachePeer *p = serverConnection()->getPeer();
        const bool peerWantsTls = p && p->secure.encryptTransport;
        // userWillTlsToPeerForUs assumes CONNECT == HTTPS
        const bool userWillTlsToPeerForUs = p && p->options.originserver &&
                                            request->method == Http::METHOD_CONNECT;
        const bool needTlsToPeer = peerWantsTls && !userWillTlsToPeerForUs;
        const bool needTlsToOrigin = !p && request->url.getScheme() == AnyP::PROTO_HTTPS;
        if (needTlsToPeer || needTlsToOrigin || request->flags.sslPeek) {
            HttpRequest::Pointer requestPointer = request;
            AsyncCall::Pointer callback = asyncCall(17,4,
                                                    "FwdState::ConnectedToPeer",
                                                    FwdStatePeerAnswerDialer(&FwdState::connectedToPeer, this));
            // Use positive timeout when less than one second is left.
            const time_t connTimeout = serverDestinations[0]->connectTimeout(start_t);
            const time_t sslNegotiationTimeout = positiveTimeout(connTimeout);
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
    }

    // if not encrypting just run the post-connect actions
    Security::EncryptorAnswer nil;
    connectedToPeer(nil);
}

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

    // should reach ConnStateData before the dispatched Client job starts
    CallJobHere1(17, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::notePeerConnection, serverConnection());

    if (serverConnection()->getPeer())
        peerConnectSucceded(serverConnection()->getPeer());

    flags.connected_okay = true;
    dispatch();
}

void
FwdState::connectTimeout(int fd)
{
    debugs(17, 2, "fwdConnectTimeout: FD " << fd << ": '" << entry->url() << "'" );
    assert(serverDestinations[0] != NULL);
    assert(fd == serverDestinations[0]->fd);

    if (entry->isEmpty()) {
        ErrorState *anErr = new ErrorState(ERR_CONNECT_FAIL, Http::scGatewayTimeout, request);
        anErr->xerrno = ETIMEDOUT;
        fail(anErr);

        /* This marks the peer DOWN ... */
        if (serverDestinations[0]->getPeer())
            peerConnectFailed(serverDestinations[0]->getPeer());
    }

    if (Comm::IsConnOpen(serverDestinations[0])) {
        serverDestinations[0]->close();
    }
}

/// called when serverConn is set to an _open_ to-peer connection
void
FwdState::syncWithServerConn(const char *host)
{
    if (Ip::Qos::TheConfig.isAclTosActive())
        Ip::Qos::setSockTos(serverConn, GetTosToServer(request));

#if SO_MARK
    if (Ip::Qos::TheConfig.isAclNfmarkActive())
        Ip::Qos::setSockNfmark(serverConn, GetNfmarkToServer(request));
#endif

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
    assert(serverDestinations.size() > 0);

    debugs(17, 3, "fwdConnectStart: " << entry->url());

    request->hier.startPeerClock();

    // Do not fowrward bumped connections to parent proxy unless it is an
    // origin server
    if (serverDestinations[0]->getPeer() && !serverDestinations[0]->getPeer()->options.originserver && request->flags.sslBumped) {
        debugs(50, 4, "fwdConnectStart: Ssl bumped connections through parent proxy are not allowed");
        ErrorState *anErr = new ErrorState(ERR_CANNOT_FORWARD, Http::scServiceUnavailable, request);
        fail(anErr);
        self = NULL; // refcounted
        return;
    }

    request->flags.pinned = false; // XXX: what if the ConnStateData set this to flag existing credentials?
    // XXX: answer: the peer selection *should* catch it and give us only the pinned peer. so we reverse the =0 step below.
    // XXX: also, logs will now lie if pinning is broken and leads to an error message.
    if (serverDestinations[0]->peerType == PINNED) {
        ConnStateData *pinned_connection = request->pinnedConnection();
        debugs(17,7, "pinned peer connection: " << pinned_connection);
        // pinned_connection may become nil after a pconn race
        serverConn = pinned_connection ? pinned_connection->borrowPinnedConnection(request, serverDestinations[0]->getPeer()) : nullptr;
        if (Comm::IsConnOpen(serverConn)) {
            flags.connected_okay = true;
            ++n_tries;
            request->flags.pinned = true;

            if (pinned_connection->pinnedAuth())
                request->flags.auth = true;

            closeHandler = comm_add_close_handler(serverConn->fd,  fwdServerClosedWrapper, this);

            syncWithServerConn(pinned_connection->pinning.host);

            // the server may close the pinned connection before this request
            pconnRace = racePossible;
            dispatch();
            return;
        }

        // Pinned connection failure.
        debugs(17,2,HERE << "Pinned connection failed: " << pinned_connection);
        ErrorState *anErr = new ErrorState(ERR_ZERO_SIZE_OBJECT, Http::scServiceUnavailable, request);
        fail(anErr);
        self = NULL; // refcounted
        return;
    }

    // Use pconn to avoid opening a new connection.
    const char *host = NULL;
    if (!serverDestinations[0]->getPeer())
        host = request->url.host();

    Comm::ConnectionPointer temp;
    // Avoid pconns after races so that the same client does not suffer twice.
    // This does not increase the total number of connections because we just
    // closed the connection that failed the race. And re-pinning assumes this.
    if (pconnRace != raceHappened)
        temp = pconnPop(serverDestinations[0], host);

    const bool openedPconn = Comm::IsConnOpen(temp);
    pconnRace = openedPconn ? racePossible : raceImpossible;

    // if we found an open persistent connection to use. use it.
    if (openedPconn) {
        serverConn = temp;
        flags.connected_okay = true;
        debugs(17, 3, HERE << "reusing pconn " << serverConnection());
        ++n_tries;

        closeHandler = comm_add_close_handler(serverConnection()->fd,  fwdServerClosedWrapper, this);

        syncWithServerConn(request->url.host());

        dispatch();
        return;
    }

    // We will try to open a new connection, possibly to the same destination.
    // We reset serverDestinations[0] in case we are using it again because
    // ConnOpener modifies its destination argument.
    serverDestinations[0]->local.port(0);
    serverConn = NULL;

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    GetMarkingsToServer(request, *serverDestinations[0]);

    calls.connector = commCbCall(17,3, "fwdConnectDoneWrapper", CommConnectCbPtrFun(fwdConnectDoneWrapper, this));
    const time_t connTimeout = serverDestinations[0]->connectTimeout(start_t);
    Comm::ConnOpener *cs = new Comm::ConnOpener(serverDestinations[0], calls.connector, connTimeout);
    if (host)
        cs->setHost(host);
    AsyncJob::Start(cs);
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

    netdbPingSite(request->url.host());

    /* Retrieves remote server TOS or MARK value, and stores it as part of the
     * original client request FD object. It is later used to forward
     * remote server's TOS/MARK in the response to the client in case of a MISS.
     */
    if (Ip::Qos::TheConfig.isHitNfmarkActive()) {
        if (Comm::IsConnOpen(clientConn) && Comm::IsConnOpen(serverConnection())) {
            fde * clientFde = &fd_table[clientConn->fd]; // XXX: move the fd_table access into Ip::Qos
            /* Get the netfilter CONNMARK */
            clientFde->nfmarkFromServer = Ip::Qos::getNfmarkFromConnection(serverConnection(), Ip::Qos::dirOpened);
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

    if (serverConnection()->getPeer() != NULL) {
        ++ serverConnection()->getPeer()->stats.fetches;
        request->peer_login = serverConnection()->getPeer()->login;
        request->peer_domain = serverConnection()->getPeer()->domain;
        request->flags.auth_no_keytab = serverConnection()->getPeer()->options.auth_no_keytab;
        httpStart(this);
    } else {
        assert(!request->flags.sslPeek);
        request->peer_login = NULL;
        request->peer_domain = NULL;
        request->flags.auth_no_keytab = 0;

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
            ErrorState *anErr = new ErrorState(ERR_UNSUP_REQ, Http::scBadRequest, request);
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

    if (!EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT)) {
        debugs(17, 3, HERE << "No, ENTRY_FWD_HDR_WAIT isn't set");
        return 0;
    }

    if (n_tries > Config.forward_max_tries)
        return 0;

    if (request->bodyNibbled())
        return 0;

    if (serverDestinations.size() <= 1) {
        // NP: <= 1 since total count includes the recently failed one.
        debugs(17, 3, HERE << "No alternative forwarding paths left");
        return 0;
    }

    const Http::StatusCode s = e->getReply()->sline.status();
    debugs(17, 3, HERE << "status " << s);
    return reforwardableStatus(s);
}

/**
 * Create "503 Service Unavailable" or "504 Gateway Timeout" error depending
 * on whether this is a validation request. RFC 2616 says that we MUST reply
 * with "504 Gateway Timeout" if validation fails and cached reply has
 * proxy-revalidate, must-revalidate or s-maxage Cache-Control directive.
 */
ErrorState *
FwdState::makeConnectingError(const err_type type) const
{
    return new ErrorState(type, request->flags.needValidation ?
                          Http::scGatewayTimeout : Http::scServiceUnavailable, request);
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

/**
 * Decide where details need to be gathered to correctly describe a persistent connection.
 * What is needed:
 *  -  the address/port details about this link
 *  -  domain name of server at other end of this link (either peer or requested host)
 */
void
FwdState::pconnPush(Comm::ConnectionPointer &conn, const char *domain)
{
    if (conn->getPeer()) {
        fwdPconnPool->push(conn, NULL);
    } else {
        fwdPconnPool->push(conn, domain);
    }
}

Comm::ConnectionPointer
FwdState::pconnPop(const Comm::ConnectionPointer &dest, const char *domain)
{
    bool retriable = checkRetriable();
    if (!retriable && Config.accessList.serverPconnForNonretriable) {
        ACLFilledChecklist ch(Config.accessList.serverPconnForNonretriable, request, NULL);
        retriable = ch.fastCheck().allowed();
    }
    // always call shared pool first because we need to close an idle
    // connection there if we have to use a standby connection.
    Comm::ConnectionPointer conn = fwdPconnPool->pop(dest, domain, retriable);
    if (!Comm::IsConnOpen(conn)) {
        // either there was no pconn to pop or this is not a retriable xaction
        if (CachePeer *peer = dest->getPeer()) {
            if (peer->standby.pool)
                conn = peer->standby.pool->pop(dest, domain, true);
        }
    }
    return conn; // open, closed, or nil
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
nfmark_t
aclMapNfmark(acl_nfmark * head, ACLChecklist * ch)
{
    for (acl_nfmark *l = head; l; l = l->next) {
        if (!l->aclList || ch->fastCheck(l->aclList).allowed())
            return l->nfmark;
    }

    return 0;
}

void
getOutgoingAddress(HttpRequest * request, Comm::ConnectionPointer conn)
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

tos_t
GetTosToServer(HttpRequest * request)
{
    ACLFilledChecklist ch(NULL, request, NULL);
    return aclMapTOS(Ip::Qos::TheConfig.tosToServer, &ch);
}

nfmark_t
GetNfmarkToServer(HttpRequest * request)
{
    ACLFilledChecklist ch(NULL, request, NULL);
    return aclMapNfmark(Ip::Qos::TheConfig.nfmarkToServer, &ch);
}

void
GetMarkingsToServer(HttpRequest * request, Comm::Connection &conn)
{
    // Get the server side TOS and Netfilter mark to be set on the connection.
    if (Ip::Qos::TheConfig.isAclTosActive()) {
        conn.tos = GetTosToServer(request);
        debugs(17, 3, "from " << conn.local << " tos " << int(conn.tos));
    }

#if SO_MARK && USE_LIBCAP
    conn.nfmark = GetNfmarkToServer(request);
    debugs(17, 3, "from " << conn.local << " netfilter mark " << conn.nfmark);
#else
    conn.nfmark = 0;
#endif
}

