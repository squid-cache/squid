/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 44    Peer Selection Algorithm */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "base/InstanceId.h"
#include "CachePeer.h"
#include "carp.h"
#include "client_side.h"
#include "dns/LookupDetails.h"
#include "errorpage.h"
#include "event.h"
#include "FwdState.h"
#include "globals.h"
#include "hier_code.h"
#include "htcp.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "icmp/net_db.h"
#include "ICP.h"
#include "ip/tools.h"
#include "ipcache.h"
#include "neighbors.h"
#include "peer_sourcehash.h"
#include "peer_userhash.h"
#include "PeerSelectState.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "util.h" // for tvSubDsec() which should be in SquidTime.h

/**
 * A CachePeer which has been selected as a possible destination.
 * Listed as pointers here so as to prevent duplicates being added but will
 * be converted to a set of IP address path options before handing back out
 * to the caller.
 *
 * Certain connection flags and outgoing settings will also be looked up and
 * set based on the received request and CachePeer settings before handing back.
 */
class FwdServer
{
    MEMPROXY_CLASS(FwdServer);

public:
    FwdServer(CachePeer *p, hier_code c) :
        _peer(p),
        code(c),
        next(nullptr)
    {}

    CbcPointer<CachePeer> _peer;                /* NULL --> origin server */
    hier_code code;
    FwdServer *next;
};

static struct {
    int timeouts;
} PeerStats;

static const char *DirectStr[] = {
    "DIRECT_UNKNOWN",
    "DIRECT_NO",
    "DIRECT_MAYBE",
    "DIRECT_YES"
};

/// a helper class to report a selected destination (for debugging)
class PeerSelectionDumper
{
public:
    PeerSelectionDumper(const PeerSelector * const aSelector, const CachePeer * const aPeer, const hier_code aCode):
        selector(aSelector), peer(aPeer), code(aCode) {}

    const PeerSelector * const selector; ///< selection parameters
    const CachePeer * const peer; ///< successful selection info
    const hier_code code; ///< selection algorithm
};

CBDATA_CLASS_INIT(PeerSelector);

/// prints PeerSelectionDumper (for debugging)
static std::ostream &
operator <<(std::ostream &os, const PeerSelectionDumper &fsd)
{
    os << hier_code_str[fsd.code];

    if (fsd.peer)
        os << '/' << fsd.peer->host;
    else if (fsd.selector) // useful for DIRECT and gone PINNED destinations
        os << '#' << fsd.selector->request->url.host();

    return os;
}

/// An ICP ping timeout service.
/// Protects event.cc (which is designed to handle a few unrelated timeouts)
/// from exposure to thousands of ping-related timeouts on busy proxies.
class PeerSelectorPingMonitor
{
public:
    /// registers the given selector to be notified about the IPC ping timeout
    void monitor(PeerSelector *);

    /// removes a PeerSelector from the waiting list
    void forget(PeerSelector *);

    /// \returns a (nil) registration of a non-waiting peer selector
    WaitingPeerSelectorPosition npos() { return selectors.end(); }

private:
    static void NoteWaitOver(void *monitor);

    void startWaiting();
    void abortWaiting();
    void noteWaitOver();

    WaitingPeerSelectors selectors; ///< \see WaitingPeerSelectors
};

/// monitors all PeerSelector ICP ping timeouts
static PeerSelectorPingMonitor &
PingMonitor()
{
    static const auto Instance = new PeerSelectorPingMonitor();
    return *Instance;
}

/* PeerSelectorPingMonitor */

/// PeerSelectorPingMonitor::noteWaitOver() wrapper
void
PeerSelectorPingMonitor::NoteWaitOver(void *raw)
{
    assert(raw);
    static_cast<PeerSelectorPingMonitor*>(raw)->noteWaitOver();
}

/// schedules a single event to represent all waiting selectors
void
PeerSelectorPingMonitor::startWaiting()
{
    assert(!selectors.empty());
    const auto interval = tvSubDsec(current_time, selectors.begin()->first);
    eventAdd("PeerSelectorPingMonitor::NoteWaitOver", &PeerSelectorPingMonitor::NoteWaitOver, this, interval, 0, false);
}

/// undoes an earlier startWaiting() call
void
PeerSelectorPingMonitor::abortWaiting()
{
    // our event may be already in the AsyncCallQueue but that is OK:
    // such queued calls cannot accumulate, and we ignore any stale ones
    eventDelete(&PeerSelectorPingMonitor::NoteWaitOver, nullptr);
}

/// calls back all ready PeerSelectors and continues to wait for others
void
PeerSelectorPingMonitor::noteWaitOver()
{
    while (!selectors.empty() && current_time >= selectors.begin()->first) {
        const auto selector = selectors.begin()->second;
        CallBack(selector->al, [selector,this] {
            selector->ping.monitorRegistration = npos();
            AsyncCall::Pointer callback = asyncCall(44, 4, "PeerSelector::HandlePingTimeout",
                cbdataDialer(PeerSelector::HandlePingTimeout, selector));
            ScheduleCallHere(callback);
        });
        selectors.erase(selectors.begin());
    }

    if (!selectors.empty()) {
        // Since abortWaiting() is unreliable, we may have been awakened by a
        // stale event A after event B has been scheduled. Now we are going to
        // schedule event C. Prevent event accumulation by deleting B (if any).
        abortWaiting();

        startWaiting();
    }
}

void
PeerSelectorPingMonitor::monitor(PeerSelector *selector)
{
    assert(selector);

    const auto deadline = selector->ping.deadline();
    const auto position = selectors.emplace(deadline, selector);
    selector->ping.monitorRegistration = position;

    if (position == selectors.begin()) {
        if (selectors.size() > 1)
            abortWaiting(); // remove the previously scheduled earlier event
        startWaiting();
    } // else the already scheduled event is still the earliest one
}

void
PeerSelectorPingMonitor::forget(PeerSelector *selector)
{
    assert(selector);

    if (selector->ping.monitorRegistration == npos())
        return; // already forgotten

    const auto wasFirst = selector->ping.monitorRegistration == selectors.begin();
    selectors.erase(selector->ping.monitorRegistration);
    selector->ping.monitorRegistration = npos();

    if (wasFirst) {
        // do not reschedule if there are still elements with the same deadline
        if (!selectors.empty() && selectors.begin()->first == selector->ping.deadline())
            return;
        abortWaiting();
        if (!selectors.empty())
            startWaiting();
    } // else do nothing since the old scheduled event is still the earliest one
}

/* PeerSelector */

PeerSelector::~PeerSelector()
{
    while (servers) {
        FwdServer *next = servers->next;
        delete servers;
        servers = next;
    }

    cancelPingTimeoutMonitoring();

    if (entry) {
        debugs(44, 3, entry->url());
        entry->ping_status = PING_DONE;
    }

    if (acl_checklist) {
        debugs(44, DBG_IMPORTANT, "BUG: peer selector gone while waiting for a slow ACL");
        delete acl_checklist;
    }

    HTTPMSGUNLOCK(request);

    if (entry) {
        assert(entry->ping_status != PING_WAITING);
        entry->unlock("peerSelect");
        entry = NULL;
    }

    delete lastError;
}

void
PeerSelector::startPingWaiting()
{
    assert(entry);
    assert(entry->ping_status != PING_WAITING);
    PingMonitor().monitor(this);
    entry->ping_status = PING_WAITING;
}

void
PeerSelector::cancelPingTimeoutMonitoring()
{
    PingMonitor().forget(this);
}

static int
peerSelectIcpPing(PeerSelector *ps, int direct, StoreEntry * entry)
{
    assert(ps);
    HttpRequest *request = ps->request;

    int n;
    assert(entry);
    assert(entry->ping_status == PING_NONE);
    assert(direct != DIRECT_YES);
    debugs(44, 3, entry->url());

    if (!request->flags.hierarchical && direct != DIRECT_NO)
        return 0;

    if (EBIT_TEST(entry->flags, KEY_PRIVATE) && !neighbors_do_private_keys)
        if (direct != DIRECT_NO)
            return 0;

    n = neighborsCount(ps);

    debugs(44, 3, "counted " << n << " neighbors");

    return n;
}

static void
peerSelect(PeerSelectionInitiator *initiator,
           HttpRequest * request,
           AccessLogEntry::Pointer const &al,
           StoreEntry * entry)
{
    if (entry)
        debugs(44, 3, *entry << ' ' << entry->url());
    else
        debugs(44, 3, request->method);

    const auto selector = new PeerSelector(initiator);

    selector->request = request;
    HTTPMSGLOCK(selector->request);
    selector->al = al;

    selector->entry = entry;

#if USE_CACHE_DIGESTS

    request->hier.peer_select_start = current_time;

#endif

    if (selector->entry)
        selector->entry->lock("peerSelect");

    selector->selectMore();
}

void
PeerSelectionInitiator::startSelectingDestinations(HttpRequest *request, const AccessLogEntry::Pointer &ale, StoreEntry *entry)
{
    subscribed = true;
    peerSelect(this, request, ale, entry);
    // and wait for noteDestination() and/or noteDestinationsEnd() calls
}

void
PeerSelector::checkNeverDirectDone(const Acl::Answer answer)
{
    acl_checklist = nullptr;
    debugs(44, 3, answer);
    never_direct = answer;
    switch (answer) {
    case ACCESS_ALLOWED:
        /** if never_direct says YES, do that. */
        direct = DIRECT_NO;
        debugs(44, 3, "direct = " << DirectStr[direct] << " (never_direct allow)");
        break;
    case ACCESS_DENIED: // not relevant.
    case ACCESS_DUNNO:  // not relevant.
        break;
    case ACCESS_AUTH_REQUIRED:
        debugs(44, DBG_IMPORTANT, "WARNING: never_direct resulted in " << answer << ". Username ACLs are not reliable here.");
        break;
    }
    selectMore();
}

void
PeerSelector::CheckNeverDirectDone(Acl::Answer answer, void *data)
{
    static_cast<PeerSelector*>(data)->checkNeverDirectDone(answer);
}

void
PeerSelector::checkAlwaysDirectDone(const Acl::Answer answer)
{
    acl_checklist = nullptr;
    debugs(44, 3, answer);
    always_direct = answer;
    switch (answer) {
    case ACCESS_ALLOWED:
        /** if always_direct says YES, do that. */
        direct = DIRECT_YES;
        debugs(44, 3, "direct = " << DirectStr[direct] << " (always_direct allow)");
        break;
    case ACCESS_DENIED: // not relevant.
    case ACCESS_DUNNO:  // not relevant.
        break;
    case ACCESS_AUTH_REQUIRED:
        debugs(44, DBG_IMPORTANT, "WARNING: always_direct resulted in " << answer << ". Username ACLs are not reliable here.");
        break;
    }
    selectMore();
}

void
PeerSelector::CheckAlwaysDirectDone(Acl::Answer answer, void *data)
{
    static_cast<PeerSelector*>(data)->checkAlwaysDirectDone(answer);
}

/// \returns true (after destroying "this") if the peer initiator is gone
/// \returns false (without side effects) otherwise
bool
PeerSelector::selectionAborted()
{
    if (interestedInitiator())
        return false;

    debugs(44, 3, "Aborting peer selection: Initiator gone or lost interest.");
    delete this;
    return true;
}

/// A single DNS resolution loop iteration: Converts selected FwdServer to IPs.
void
PeerSelector::resolveSelected()
{
    if (selectionAborted())
        return;

    FwdServer *fs = servers;

    // Bug 3243: CVE 2009-0801
    // Bypass of browser same-origin access control in intercepted communication
    // To resolve this we must use only the original client destination when going DIRECT
    // on intercepted traffic which failed Host verification
    const HttpRequest *req = request;
    const bool isIntercepted = !req->flags.redirected &&
                               (req->flags.intercepted || req->flags.interceptTproxy);
    const bool useOriginalDst = Config.onoff.client_dst_passthru || !req->flags.hostVerified;
    const bool choseDirect = fs && fs->code == HIER_DIRECT;
    if (isIntercepted && useOriginalDst && choseDirect) {
        // check the client is still around before using any of its details
        if (req->clientConnectionManager.valid()) {
            // construct a "result" adding the ORIGINAL_DST to the set instead of DIRECT
            Comm::ConnectionPointer p = new Comm::Connection();
            p->remote = req->clientConnectionManager->clientConnection->local;
            fs->code = ORIGINAL_DST; // fs->code is DIRECT. This fixes the display.
            handlePath(p, *fs);
        }

        // clear the used fs and continue
        servers = fs->next;
        delete fs;
        resolveSelected();
        return;
    }

    if (fs && fs->code == PINNED) {
        // Nil path signals a PINNED destination selection. Our initiator should
        // borrow and use clientConnectionManager's pinned connection object
        // (regardless of that connection destination).
        handlePath(nullptr, *fs);
        servers = fs->next;
        delete fs;
        resolveSelected();
        return;
    }

    // convert the list of FwdServer destinations into destinations IP addresses
    if (fs && wantsMoreDestinations()) {
        // send the next one off for DNS lookup.
        const char *host = fs->_peer.valid() ? fs->_peer->host : request->url.host();
        debugs(44, 2, "Find IP destination for: " << url() << "' via " << host);
        Dns::nbgethostbyname(host, this);
        return;
    }

    // Bug 3605: clear any extra listed FwdServer destinations, when the options exceeds max_foward_tries.
    // due to the allocation method of fs, we must deallocate each manually.
    // TODO: use a std::list so we can get the size and abort adding whenever the selection loops reach Config.forward_max_tries
    if (fs) {
        assert(fs == servers);
        while (fs) {
            servers = fs->next;
            delete fs;
            fs = servers;
        }
    }

    // done with DNS lookups. pass back to caller

    debugs(44, 2, id << " found all " << foundPaths << " destinations for " << url());
    debugs(44, 2, "  always_direct = " << always_direct);
    debugs(44, 2, "   never_direct = " << never_direct);
    debugs(44, 2, "       timedout = " << ping.timedout);

    ping.stop = current_time;
    request->hier.ping = ping; // final result

    if (lastError && foundPaths) {
        // nobody cares about errors if we found destinations despite them
        debugs(44, 3, "forgetting the last error");
        delete lastError;
        lastError = nullptr;
    }

    if (const auto initiator = interestedInitiator())
        initiator->noteDestinationsEnd(lastError);
    lastError = nullptr; // initiator owns the ErrorState object now
    delete this;
}

void
PeerSelector::noteLookup(const Dns::LookupDetails &details)
{
    /* ignore lookup delays that occurred after the initiator moved on */

    if (selectionAborted())
        return;

    if (!wantsMoreDestinations())
        return;

    request->recordLookup(details);
}

void
PeerSelector::noteIp(const Ip::Address &ip)
{
    if (selectionAborted())
        return;

    if (!wantsMoreDestinations())
        return;

    const auto peer = servers->_peer.valid();

    // for TPROXY spoofing, we must skip unusable addresses
    if (request->flags.spoofClientIp && !(peer && peer->options.no_tproxy) ) {
        if (ip.isIPv4() != request->client_addr.isIPv4())
            return; // cannot spoof the client address on this link
    }

    Comm::ConnectionPointer p = new Comm::Connection();
    p->remote = ip;
    p->remote.port(peer ? peer->http_port : request->url.port());
    handlePath(p, *servers);
}

void
PeerSelector::noteIps(const Dns::CachedIps *ia, const Dns::LookupDetails &details)
{
    if (selectionAborted())
        return;

    FwdServer *fs = servers;
    if (!ia) {
        debugs(44, 3, "Unknown host: " << (fs->_peer.valid() ? fs->_peer->host : request->url.host()));
        // discard any previous error.
        delete lastError;
        lastError = NULL;
        if (fs->code == HIER_DIRECT) {
            lastError = new ErrorState(ERR_DNS_FAIL, Http::scServiceUnavailable, request, al);
            lastError->dnsError = details.error;
        }
    }
    // else noteIp() calls have already processed all IPs in *ia

    servers = fs->next;
    delete fs;

    // continue resolving selected peers
    resolveSelected();
}

int
PeerSelector::checkNetdbDirect()
{
#if USE_ICMP
    CachePeer *p;
    int myrtt;
    int myhops;

    if (direct == DIRECT_NO)
        return 0;

    /* base lookup on RTT and Hops if ICMP NetDB is enabled. */

    myrtt = netdbHostRtt(request->url.host());
    debugs(44, 3, "MY RTT = " << myrtt << " msec");
    debugs(44, 3, "minimum_direct_rtt = " << Config.minDirectRtt << " msec");

    if (myrtt && myrtt <= Config.minDirectRtt)
        return 1;

    myhops = netdbHostHops(request->url.host());

    debugs(44, 3, "MY hops = " << myhops);
    debugs(44, 3, "minimum_direct_hops = " << Config.minDirectHops);

    if (myhops && myhops <= Config.minDirectHops)
        return 1;

    p = whichPeer(closest_parent_miss);

    if (p == NULL)
        return 0;

    debugs(44, 3, "closest_parent_miss RTT = " << ping.p_rtt << " msec");

    if (myrtt && myrtt <= ping.p_rtt)
        return 1;

#endif /* USE_ICMP */

    return 0;
}

void
PeerSelector::selectMore()
{
    if (selectionAborted())
        return;

    debugs(44, 3, request->method << ' ' << request->url.host());

    /** If we don't know whether DIRECT is permitted ... */
    if (direct == DIRECT_UNKNOWN) {
        if (always_direct == ACCESS_DUNNO) {
            debugs(44, 3, "direct = " << DirectStr[direct] << " (always_direct to be checked)");
            /** check always_direct; */
            ACLFilledChecklist *ch = new ACLFilledChecklist(Config.accessList.AlwaysDirect, request, NULL);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request, nullptr);
            acl_checklist->nonBlockingCheck(CheckAlwaysDirectDone, this);
            return;
        } else if (never_direct == ACCESS_DUNNO) {
            debugs(44, 3, "direct = " << DirectStr[direct] << " (never_direct to be checked)");
            /** check never_direct; */
            ACLFilledChecklist *ch = new ACLFilledChecklist(Config.accessList.NeverDirect, request, NULL);
            ch->al = al;
            acl_checklist = ch;
            acl_checklist->syncAle(request, nullptr);
            acl_checklist->nonBlockingCheck(CheckNeverDirectDone, this);
            return;
        } else if (request->flags.noDirect) {
            /** if we are accelerating, direct is not an option. */
            direct = DIRECT_NO;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (forced non-direct)");
        } else if (request->flags.loopDetected) {
            /** if we are in a forwarding-loop, direct is not an option. */
            direct = DIRECT_YES;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (forwarding loop detected)");
        } else if (checkNetdbDirect()) {
            direct = DIRECT_YES;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (checkNetdbDirect)");
        } else {
            direct = DIRECT_MAYBE;
            debugs(44, 3, "direct = " << DirectStr[direct] << " (default)");
        }

        debugs(44, 3, "direct = " << DirectStr[direct]);
    }

    if (!entry || entry->ping_status == PING_NONE)
        selectPinned();
    if (entry == NULL) {
        (void) 0;
    } else if (entry->ping_status == PING_NONE) {
        selectSomeNeighbor();

        if (entry->ping_status == PING_WAITING)
            return;
    } else if (entry->ping_status == PING_WAITING) {
        selectSomeNeighborReplies();
        cancelPingTimeoutMonitoring();
        entry->ping_status = PING_DONE;
    }

    switch (direct) {

    case DIRECT_YES:
        selectSomeDirect();
        break;

    case DIRECT_NO:
        selectSomeParent();
        selectAllParents();
        break;

    default:

        if (Config.onoff.prefer_direct)
            selectSomeDirect();

        if (request->flags.hierarchical || !Config.onoff.nonhierarchical_direct) {
            selectSomeParent();
            selectAllParents();
        }

        if (!Config.onoff.prefer_direct)
            selectSomeDirect();

        break;
    }

    // end peer selection; start resolving selected peers
    resolveSelected();
}

bool peerAllowedToUse(const CachePeer *, PeerSelector*);

/// Selects a pinned connection if it exists, is valid, and is allowed.
void
PeerSelector::selectPinned()
{
    // TODO: Avoid all repeated calls. Relying on PING_DONE is not enough.
    if (!request->pinnedConnection())
        return;

    const auto peer = request->pinnedConnection()->pinnedPeer();
    const auto usePinned = peer ? peerAllowedToUse(peer, this) : (direct != DIRECT_NO);
    // If the pinned connection is prohibited (for this request) then
    // the initiator must decide whether it is OK to open a new one instead.
    request->pinnedConnection()->pinning.peerAccessDenied = !usePinned;

    addSelection(peer, PINNED);
    if (entry)
        entry->ping_status = PING_DONE; // skip ICP
}

/**
 * Selects a neighbor (parent or sibling) based on one of the
 * following methods:
 *      Cache Digests
 *      CARP
 *      ICMP Netdb RTT estimates
 *      ICP/HTCP queries
 */
void
PeerSelector::selectSomeNeighbor()
{
    CachePeer *p;
    hier_code code = HIER_NONE;
    assert(entry->ping_status == PING_NONE);

    if (direct == DIRECT_YES) {
        entry->ping_status = PING_DONE;
        return;
    }

#if USE_CACHE_DIGESTS
    if ((p = neighborsDigestSelect(this))) {
        if (neighborType(p, request->url) == PEER_PARENT)
            code = CD_PARENT_HIT;
        else
            code = CD_SIBLING_HIT;
    } else
#endif
        if ((p = netdbClosestParent(this))) {
            code = CLOSEST_PARENT;
        } else if (peerSelectIcpPing(this, direct, entry)) {
            debugs(44, 3, "Doing ICP pings");
            ping.start = current_time;
            ping.n_sent = neighborsUdpPing(request,
                                           entry,
                                           HandlePingReply,
                                           this,
                                           &ping.n_replies_expected,
                                           &ping.timeout);
            // TODO: Refactor neighborsUdpPing() to guarantee positive timeouts.
            if (ping.timeout < 0)
                ping.timeout = 0;

            if (ping.n_sent == 0)
                debugs(44, DBG_CRITICAL, "WARNING: neighborsUdpPing returned 0");
            debugs(44, 3, ping.n_replies_expected <<
                   " ICP replies expected, RTT " << ping.timeout <<
                   " msec");

            if (ping.n_replies_expected > 0) {
                startPingWaiting();
                return;
            }
        }

    if (code != HIER_NONE) {
        assert(p);
        addSelection(p, code);
    }

    entry->ping_status = PING_DONE;
}

/// Selects a neighbor (parent or sibling) based on ICP/HTCP replies.
void
PeerSelector::selectSomeNeighborReplies()
{
    CachePeer *p = NULL;
    hier_code code = HIER_NONE;
    assert(entry->ping_status == PING_WAITING);
    assert(direct != DIRECT_YES);

    if (checkNetdbDirect()) {
        code = CLOSEST_DIRECT;
        addSelection(nullptr, code);
        return;
    }

    if ((p = hit)) {
        code = hit_type == PEER_PARENT ? PARENT_HIT : SIBLING_HIT;
    } else {
        if (!closest_parent_miss.isAnyAddr()) {
            p = whichPeer(closest_parent_miss);
            code = CLOSEST_PARENT_MISS;
        } else if (!first_parent_miss.isAnyAddr()) {
            p = whichPeer(first_parent_miss);
            code = FIRST_PARENT_MISS;
        }
    }
    if (p && code != HIER_NONE) {
        addSelection(p, code);
    }
}

/// Adds a "direct" entry if the request can be forwarded to the origin server.
void
PeerSelector::selectSomeDirect()
{
    if (direct == DIRECT_NO)
        return;

    /* WAIS is not implemented natively */
    if (request->url.getScheme() == AnyP::PROTO_WAIS)
        return;

    addSelection(nullptr, HIER_DIRECT);
}

void
PeerSelector::selectSomeParent()
{
    CachePeer *p;
    hier_code code = HIER_NONE;
    debugs(44, 3, request->method << ' ' << request->url.host());

    if (direct == DIRECT_YES)
        return;

    if ((p = peerSourceHashSelectParent(this))) {
        code = SOURCEHASH_PARENT;
#if USE_AUTH
    } else if ((p = peerUserHashSelectParent(this))) {
        code = USERHASH_PARENT;
#endif
    } else if ((p = carpSelectParent(this))) {
        code = CARP;
    } else if ((p = getRoundRobinParent(this))) {
        code = ROUNDROBIN_PARENT;
    } else if ((p = getWeightedRoundRobinParent(this))) {
        code = ROUNDROBIN_PARENT;
    } else if ((p = getFirstUpParent(this))) {
        code = FIRSTUP_PARENT;
    } else if ((p = getDefaultParent(this))) {
        code = DEFAULT_PARENT;
    }

    if (code != HIER_NONE) {
        addSelection(p, code);
    }
}

/// Adds alive parents. Used as a last resort for never_direct.
void
PeerSelector::selectAllParents()
{
    CachePeer *p;
    /* Add all alive parents */

    for (p = Config.peers; p; p = p->next) {
        /* XXX: neighbors.c lacks a public interface for enumerating
         * parents to a request so we have to dig some here..
         */

        if (neighborType(p, request->url) != PEER_PARENT)
            continue;

        if (!peerHTTPOkay(p, this))
            continue;

        addSelection(p, ANY_OLD_PARENT);
    }

    /* XXX: should add dead parents here, but it is currently
     * not possible to find out which parents are dead or which
     * simply are not configured to handle the request.
     */
    /* Add default parent as a last resort */
    if ((p = getDefaultParent(this))) {
        addSelection(p, DEFAULT_PARENT);
    }
}

void
PeerSelector::handlePingTimeout()
{
    debugs(44, 3, url());

    // do nothing if ping reply came while handlePingTimeout() was queued
    if (!entry || entry->ping_status != PING_WAITING)
        return;

    entry->ping_status = PING_DONE;

    if (selectionAborted())
        return;

    ++PeerStats.timeouts;
    ping.timedout = 1;
    selectMore();
}

void
PeerSelector::HandlePingTimeout(PeerSelector *selector)
{
    selector->handlePingTimeout();
}

void
peerSelectInit(void)
{
    memset(&PeerStats, '\0', sizeof(PeerStats));
}

void
PeerSelector::handleIcpParentMiss(CachePeer *p, icp_common_t *header)
{
    int rtt;

#if USE_ICMP
    if (Config.onoff.query_icmp) {
        if (header->flags & ICP_FLAG_SRC_RTT) {
            rtt = header->pad & 0xFFFF;
            int hops = (header->pad >> 16) & 0xFFFF;

            if (rtt > 0 && rtt < 0xFFFF)
                netdbUpdatePeer(request->url, p, rtt, hops);

            if (rtt && (ping.p_rtt == 0 || rtt < ping.p_rtt)) {
                closest_parent_miss = p->in_addr;
                ping.p_rtt = rtt;
            }
        }
    }
#endif /* USE_ICMP */

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (!closest_parent_miss.isAnyAddr())
        return;

    rtt = (tvSubMsec(ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (first_parent_miss.isAnyAddr() || rtt < ping.w_rtt) {
        first_parent_miss = p->in_addr;
        ping.w_rtt = rtt;
    }
}

void
PeerSelector::handleIcpReply(CachePeer *p, const peer_t type, icp_common_t *header)
{
    icp_opcode op = header->getOpCode();
    debugs(44, 3, icp_opcode_str[op] << ' ' << url());
#if USE_CACHE_DIGESTS && 0
    /* do cd lookup to count false misses */

    if (p && request)
        peerNoteDigestLookup(request, p,
                             peerDigestLookup(p, this));

#endif

    ++ping.n_recv;

    if (op == ICP_MISS || op == ICP_DECHO) {
        if (type == PEER_PARENT)
            handleIcpParentMiss(p, header);
    } else if (op == ICP_HIT) {
        hit = p;
        hit_type = type;
        selectMore();
        return;
    }

    if (ping.n_recv < ping.n_replies_expected)
        return;

    selectMore();
}

#if USE_HTCP
void
PeerSelector::handleHtcpReply(CachePeer *p, const peer_t type, HtcpReplyData *htcp)
{
    debugs(44, 3, (htcp->hit ? "HIT" : "MISS") << ' ' << url());
    ++ping.n_recv;

    if (htcp->hit) {
        hit = p;
        hit_type = type;
        selectMore();
        return;
    }

    if (type == PEER_PARENT)
        handleHtcpParentMiss(p, htcp);

    if (ping.n_recv < ping.n_replies_expected)
        return;

    selectMore();
}

void
PeerSelector::handleHtcpParentMiss(CachePeer *p, HtcpReplyData *htcp)
{
    int rtt;

#if USE_ICMP
    if (Config.onoff.query_icmp) {
        if (htcp->cto.rtt > 0) {
            rtt = (int) htcp->cto.rtt * 1000;
            int hops = (int) htcp->cto.hops * 1000;
            netdbUpdatePeer(request->url, p, rtt, hops);

            if (rtt && (ping.p_rtt == 0 || rtt < ping.p_rtt)) {
                closest_parent_miss = p->in_addr;
                ping.p_rtt = rtt;
            }
        }
    }
#endif /* USE_ICMP */

    /* if closest-only is set, then don't allow FIRST_PARENT_MISS */
    if (p->options.closest_only)
        return;

    /* set FIRST_MISS if there is no CLOSEST parent */
    if (!closest_parent_miss.isAnyAddr())
        return;

    rtt = (tvSubMsec(ping.start, current_time) - p->basetime) / p->weight;

    if (rtt < 1)
        rtt = 1;

    if (first_parent_miss.isAnyAddr() || rtt < ping.w_rtt) {
        first_parent_miss = p->in_addr;
        ping.w_rtt = rtt;
    }
}

#endif

void
PeerSelector::HandlePingReply(CachePeer * p, peer_t type, AnyP::ProtocolType proto, void *pingdata, void *data)
{
    if (proto == AnyP::PROTO_ICP)
        static_cast<PeerSelector*>(data)->handleIcpReply(p, type, static_cast<icp_common_t*>(pingdata));

#if USE_HTCP

    else if (proto == AnyP::PROTO_HTCP)
        static_cast<PeerSelector*>(data)->handleHtcpReply(p, type, static_cast<HtcpReplyData*>(pingdata));

#endif

    else
        debugs(44, DBG_IMPORTANT, "ERROR: ignoring an ICP reply with unknown protocol " << proto);
}

void
PeerSelector::addSelection(CachePeer *peer, const hier_code code)
{
    // Find the end of the servers list. Bail on a duplicate destination.
    auto **serversTail = &servers;
    while (const auto server = *serversTail) {
        // There can be at most one PINNED destination.
        // Non-PINNED destinations are uniquely identified by their CachePeer
        // (even though a DIRECT destination might match a cache_peer address).
        // XXX: We may still add duplicates because the same peer could have
        // been removed from `servers` already (and given to the requestor).
        const bool duplicate = (server->code == PINNED) ?
                               (code == PINNED) : (server->_peer == peer);
        if (duplicate) {
            debugs(44, 3, "skipping " << PeerSelectionDumper(this, peer, code) <<
                   "; have " << PeerSelectionDumper(this, server->_peer.get(), server->code));
            return;
        }
        serversTail = &server->next;
    }

    debugs(44, 3, "adding " << PeerSelectionDumper(this, peer, code));
    *serversTail = new FwdServer(peer, code);
}

PeerSelector::PeerSelector(PeerSelectionInitiator *initiator):
    request(nullptr),
    entry (NULL),
    always_direct(Config.accessList.AlwaysDirect?ACCESS_DUNNO:ACCESS_DENIED),
    never_direct(Config.accessList.NeverDirect?ACCESS_DUNNO:ACCESS_DENIED),
    direct(DIRECT_UNKNOWN),
    lastError(NULL),
    servers (NULL),
    first_parent_miss(),
    closest_parent_miss(),
    hit(NULL),
    hit_type(PEER_NONE),
    acl_checklist (NULL),
    initiator_(initiator)
{
    ; // no local defaults.
}

const SBuf
PeerSelector::url() const
{
    if (entry)
        return SBuf(entry->url());

    if (request)
        return request->effectiveRequestUri();

    static const SBuf noUrl("[no URL]");
    return noUrl;
}

/// \returns valid/interested peer initiator or nil
PeerSelectionInitiator *
PeerSelector::interestedInitiator()
{
    const auto initiator = initiator_.valid();

    if (!initiator) {
        debugs(44, 3, id << " initiator gone");
        return nullptr;
    }

    if (!initiator->subscribed) {
        debugs(44, 3, id << " initiator lost interest");
        return nullptr;
    }

    debugs(44, 7, id);
    return initiator;
}

bool
PeerSelector::wantsMoreDestinations() const {
    const auto maxCount = Config.forward_max_tries;
    return maxCount >= 0 && foundPaths <
           static_cast<std::make_unsigned<decltype(maxCount)>::type>(maxCount);
}

void
PeerSelector::handlePath(const Comm::ConnectionPointer &path, FwdServer &fs)
{
    ++foundPaths;

    if (path) {
        path->peerType = fs.code;
        path->setPeer(fs._peer.get());

        // check for a configured outgoing address for this destination...
        getOutgoingAddress(request, path);
        debugs(44, 2, id << " found " << path << ", destination #" << foundPaths << " for " << url());
    } else
        debugs(44, 2, id << " found pinned, destination #" << foundPaths << " for " << url());

    request->hier.ping = ping; // may be updated later

    debugs(44, 2, "  always_direct = " << always_direct);
    debugs(44, 2, "   never_direct = " << never_direct);
    debugs(44, 2, "       timedout = " << ping.timedout);

    if (const auto initiator = interestedInitiator())
        initiator->noteDestination(path);
}

InstanceIdDefinitions(PeerSelector, "PeerSelector");

ping_data::ping_data() :
    n_sent(0),
    n_recv(0),
    n_replies_expected(0),
    timeout(0),
    timedout(0),
    w_rtt(0),
    p_rtt(0),
    monitorRegistration(PingMonitor().npos())
{
    start.tv_sec = 0;
    start.tv_usec = 0;
    stop.tv_sec = 0;
    stop.tv_usec = 0;
}

timeval
ping_data::deadline() const
{
    timeval timeInterval;
    timeInterval.tv_sec = timeout / 1000;
    timeInterval.tv_usec = (timeout % 1000) * 1000;

    timeval result;
    tvAdd(result, start, timeInterval);
    return result;
}

