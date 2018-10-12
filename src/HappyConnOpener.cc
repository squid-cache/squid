#include "squid.h"
#include "CachePeer.h"
#include "FwdState.h"
#include "HappyConnOpener.h"
#include "HttpRequest.h"
#include "ip/QosConfig.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "ResolvedPeers.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(HappyConnOpener);

static PconnPool *fwdPconnPool = new PconnPool("server-peers", NULL);

int HappyConnOpener::SpareConnects = 0;
double HappyConnOpener::LastSpareAttempt = 0;

/// Manages a queue of HappyConnOpeners objects waiting the preconditions
/// to be satisfied in order to start an attempt for a new spare connection
class HappyConnQueue {
public:
    /// Schedule the next check for starting new connection attempts
    void scheduleConnectorsListCheck();

    /// \return pointer to the first valid connector in queue or nil
    //const HappyConnOpener::Pointer &frontOpener();
    void kickSparesLimitQueue();

    AsyncCall::Pointer queueASpareConnection(HappyConnOpener::Pointer happy);

    /// The time period after which the next spare connection can be started
    /// It takes in account the happy_eyeballs_connect_gap and the
    /// happy_eyeballs_connect_timeout.
    double spareMayStartAfter(const HappyConnOpener::Pointer &happy) const;

    ///< \return true if the happy_eyeballs_connect_timeout precondition
    /// satisfied
    bool primeConnectTooSlow(const HappyConnOpener::Pointer &happy) const;

    /// The configured connect_limit per worker basis
    static int ConnectLimit();

    /// The configured connect_gap per worker basis
    static int ConnectGap();

    /// True if the system preconditions for starting a new spare connection
    /// which defined by happy_eyeballs_connect_limit configuration parameter
    /// is satisfied.
    static bool GapRule();

    /// True if the system preconditions for starting a new spare connection
    /// which defined by happy_eyeballs_connect_gap configuration parameter
    /// is satisfied
    static bool ConnectionsLimitRule();

    /// Event which checks for the next spare connection
    static void SpareConnectionAttempt(void *data);

    /// The list of connectors waiting to start a new spare connection attempt
    /// when system and current request preconditions satisfied.
    std::list<AsyncCall::Pointer> waitingForSpareQueue;
    std::list<AsyncCall::Pointer> sparesLimitQueue;

    bool waitEvent = false;
};

HappyConnQueue HappyQueue;

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer)
{
    return os << answer.conn << ", " << answer.ioStatus << ", " << answer.xerrno << ", " << (answer.reused ? "reused" : "new");
}

HappyConnOpener::HappyConnOpener(const ResolvedPeers::Pointer &destinations, const AsyncCall::Pointer &aCall, const time_t fwdStart, int tries):
    AsyncJob("HappyConnOpener"),
    useTos(0),
    useNfmark(0),
    callback_(aCall),
    dests_(destinations),
    allowPconn_(true),
    retriable_(true),
    sparePermitted(false),
    host_(nullptr),
    fwdStart_(fwdStart),
    maxTries(tries),
    n_tries(0)
{
    assert(dynamic_cast<HappyConnOpener::CbDialer *>(callback_->getDialer()));
}

HappyConnOpener::~HappyConnOpener()
{
    safe_free(host_);
    debugs(17,5, "destroyed");
}

void
HappyConnOpener::setHost(const char *h)
{
    safe_free(host_);
    if (h)
        host_ = xstrdup(h);
}

void
HappyConnOpener::start()
{
    debugs(17, 8, "Start connecting");
    checkForNewConnection();
}

bool
HappyConnOpener::doneAll() const
{
    if (!callback_)
        return true; // (probably found a good path and) informed the requestor
    if (callback_->canceled())
        return true; // the requestor is gone or has lost interest
    if (!prime && !spare && dests_->empty() && dests_->destinationsFinalized)
        return true; // there are no more paths to try
    return false;
}

void
HappyConnOpener::swanSong()
{
    debugs(17,5, "HappyConnOpener::swanSong: Job finished, cleanup");
    if (callback_)
        callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "Found no usable destinations");

    // TODO: These call cancellations should not be needed.

    if (waitingForSparePermission)
        cancelSpareWait("HappyConnOpener object destructed");

    if (prime.path) {
        if (prime.connector)
            prime.connector->cancel("HappyConnOpener object destructed");
        prime.connector = nullptr;
        prime.path = nullptr;
    }

    if (!spare.path) {
        if (spare.connector)
            spare.connector->cancel("HappyConnOpener object destructed");
        spare.connector = nullptr;
        spare.path = nullptr;
    }

    AsyncJob::swanSong();
}

void
HappyConnOpener::callCallback(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno, bool reused, const char *msg)
{
    if (callback_ && !callback_->canceled()) {
        HappyConnOpener::CbDialer *cd = dynamic_cast<HappyConnOpener::CbDialer *>(callback_->getDialer());
        cd->answer_.conn = conn;
        cd->answer_.host = nullptr;
        cd->answer_.ioStatus = err;
        cd->answer_.xerrno = xerrno;
        cd->answer_.status = msg;
        cd->answer_.n_tries = n_tries;
        cd->answer_.reused = reused;
        ScheduleCallHere(callback_);
    }
    callback_ = nullptr;
}

void
HappyConnOpener::noteCandidatesChange()
{
    assert(dests_);
    debugs(17, 7, "destinations: " << dests_->size() << " finalized: " << dests_->destinationsFinalized);
    checkForNewConnection();
}

// XXX: Rename pconn into something that does not clash with "persistent connection"
void
HappyConnOpener::startConnecting(PendingConnection &pconn, Comm::ConnectionPointer &dest)
{
    Must(!pconn.path);
    Must(!pconn.connector);

    // Use pconn to avoid opening a new connection.
    Comm::ConnectionPointer temp;
    if (allowPconn_)
        temp = PconnPop(dest, (dest->getPeer() ? nullptr : host_), retriable_);

    const bool openedPconn = Comm::IsConnOpen(temp);

    // if we found an open persistent connection to use. use it.
    if (openedPconn) {
        pconn.path = temp;
        pconn.connector = nullptr;
        ++n_tries;
        callCallback(temp, Comm::OK, 0, true, "reusing pconn");
        return;
    }

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    //GetMarkingsToServer(request, *dest);
    dest->tos = useTos;
    dest->nfmark = useNfmark;

    dest->local.port(0);
    ++n_tries;

    typedef CommCbMemFunT<HappyConnOpener, CommConnectCbParams> Dialer;
    AsyncCall::Pointer callConnect = JobCallback(48, 5, Dialer, this, HappyConnOpener::connectDone);
    const time_t connTimeout = dest->connectTimeout(fwdStart_);
    Comm::ConnOpener *cs = new Comm::ConnOpener(dest, callConnect, connTimeout);
    if (!dest->getPeer())
        cs->setHost(host_);

    pconn.path = dest;
    pconn.connector = callConnect;

    lastAttemptTime = current_dtime;
    AsyncJob::Start(cs);
}

void
HappyConnOpener::connectDone(const CommConnectCbParams &params)
{
    Must(params.conn);
    const bool itWasPrime = (params.conn == prime.path);
    const bool itWasSpare = (params.conn == spare.path);
    Must(itWasPrime != itWasSpare);
    const char *what = itWasPrime ? "prime connection" : "spare connection";

    if (itWasPrime) {
        prime.path = nullptr;
        prime.connector = nullptr;
    } else {
        spare.path = nullptr;
        spare.connector = nullptr;
        --SpareConnects;
        HappyQueue.kickSparesLimitQueue();
    }

    if (params.flag == Comm::OK) {
        callCallback(params.conn, Comm::OK, 0, false, what);
        return;
    }

    debugs(17, 8, what << " failed: " << params.conn);
    if (const auto peer = params.conn->getPeer())
        peerConnectFailed(peer);
    params.conn->close(); // TODO: Comm::ConnOpener should do this instead.

    if (waitingForSparePermission) {
        cancelSpareWait("prime failure");
        sparePermitted = true;
    }

    checkForNewConnection();
}

/// stops waiting for a spare gap to expire
void
HappyConnOpener::cancelSpareWait(const char *reason)
{
    if (waitingForSparePermission) {
        waitingForSparePermission->cancel(reason);
        waitingForSparePermission = nullptr;
    }
}


/** Called when an external event changes dests_, prime, spare, or sparePermitted.
 * Leaves HappyConnOpener in one of these (mutually exclusive) "stable" states:
 *
 * 1. Processing a single peer: currentPeer
 *    1.1. Connecting: prime || spare
 *    1.2. Waiting for spare gap and/or paths: !prime && !spare
 * 2. Waiting for a new peer: dests-empty() && !dests_->destinationsFinalized && !currentPeer
 * 3. Done: dests-empty() && dests_->destinationsFinalized && !currentPeer
 */
void
HappyConnOpener::checkForNewConnection()
{
    assert(dests_); // TODO: remove this and others
    debugs(17, 7, "destinations: " << dests_->size() << " finalized: " << dests_->destinationsFinalized);

    // The order of the top-level if-statements below is important.

    // update stale waitingForSparePermission and currentPeer
    if (currentPeer && !spare && dests_->doneWithPeer(*currentPeer)) {
        if (waitingForSparePermission)
            cancelSpareWait("no spares are coming");
        else
            sparePermitted = false;

        if (!prime) {
            debugs(17, 7, "done with peer; " << *currentPeer);
            currentPeer = nullptr;
        }
    }

    // open new prime and/or spare connections if needed
    if (!dests_->empty()) {
        if (!currentPeer) {
            currentPeer = dests_->extractFront();
            Must(currentPeer);
            debugs(17, 7, "done waiting for a new peer; got " << *currentPeer);
            startConnecting(prime, currentPeer);
            maybeStartWaitingForSpare();
            Must(prime); // entering state #1.1
            return;
        }

        if (!prime)
            maybeOpenAnotherPrimeConnection(); // may make dests_ empty()

        if (!spare && sparePermitted)
            maybeOpenSpareConnection(); // may make dests_ empty()

        Must(currentPeer);
    }

    if (currentPeer) {
        debugs(17, 7, "keep working on " << *currentPeer);
        return; // remaining in state #1.1 or #1.2
    }

    if (!dests_->destinationsFinalized) {
        debugs(17, 7, "keep waiting for more peers");
        Must(!currentPeer);
        return; // remaining in state #2
    }

    debugs(17, 7, "done; no more peers");
    Must(doneAll());
    // entering state #3
}

/// called when we were allowed to open one spare connection
void
HappyConnOpener::noteSpareAllowed()
{
    waitingForSparePermission = nullptr;
    sparePermitted = true;
    checkForNewConnection();
}

/**
 * Decide where details need to be gathered to correctly describe a persistent connection.
 * What is needed:
 *  -  the address/port details about this link
 *  -  domain name of server at other end of this link (either peer or requested host)
 */
void
HappyConnOpener::PconnPush(Comm::ConnectionPointer &conn, const char *domain)
{
    if (conn->getPeer()) {
        fwdPconnPool->push(conn, NULL);
    } else {
        fwdPconnPool->push(conn, domain);
    }
}

Comm::ConnectionPointer
HappyConnOpener::PconnPop(const Comm::ConnectionPointer &dest, const char *domain, bool retriable)
{
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
HappyConnOpener::ConnectionClosed(const Comm::ConnectionPointer &conn)
{
    fwdPconnPool->noteUses(fd_table[conn->fd].pconn.uses);
}

/// starts a prime connection attempt if possible or does nothing otherwise
void
HappyConnOpener::maybeOpenAnotherPrimeConnection()
{
    Must(currentPeer);

    if (auto dest = dests_->extractPrime(*currentPeer)) {
        startConnecting(prime, dest);
        return;
    }

    debugs(17, 8, "no more prime addresses for " << *currentPeer);
}

/// starts waiting for a spare permission (if spare connections may be possible)
/// or does nothing (otherwise)
void
HappyConnOpener::maybeStartWaitingForSpare()
{
    Must(currentPeer);
    Must(prime); // or we should be opening, not waiting
    Must(!spare);
    Must(!waitingForSparePermission);
    Must(!sparePermitted);

    if (dests_->doneWithSpare(*currentPeer)) {
        debugs(17, 7, "no spares for " << *currentPeer);
        return;
    }

    waitingForSparePermission = HappyQueue.queueASpareConnection(HappyConnOpener::Pointer(this));
}

/// starts a spare connection attempt if possible
void
HappyConnOpener::maybeOpenSpareConnection()
{
    Must(currentPeer);
    Must(!spare);
    Must(!waitingForSparePermission);
    Must(sparePermitted);

    if (auto dest = dests_->extractSpare(*currentPeer)) {
        ++SpareConnects;
        LastSpareAttempt = current_dtime;
        startConnecting(spare, dest);
        return;
    }

    debugs(17, 7, "waiting for spare paths to " << *currentPeer);
}

AsyncCall::Pointer
HappyConnQueue::queueASpareConnection(HappyConnOpener::Pointer happy)
{
    if (ConnectLimit() == 0) {
        debugs(17, 8, "Spare connections are disabled");
        static AsyncCall::Pointer nil;
        return nil;
    }

    bool needsSpareNow = primeConnectTooSlow(happy);
    bool gapRuleOK = GapRule();
    bool connectionsLimitRuleOK = ConnectionsLimitRule();
    bool startSpareNow = happy->sparesBlockedOnCandidatePaths ||
                         (needsSpareNow && gapRuleOK && connectionsLimitRuleOK);

    typedef NullaryMemFunT<HappyConnOpener> Dialer;
    AsyncCall::Pointer call = JobCallback(17, 5, Dialer, happy, HappyConnOpener::noteSpareAllowed);
    if (startSpareNow) {
        ScheduleCallHere(call);
        return call;
    }

    if (needsSpareNow && gapRuleOK /*&& !connectionsLimitRuleOK*/) {
        debugs(17, 8, "A new attempt should start as soon as possible");
        sparesLimitQueue.push_back(call);
    } else {
        debugs(17, 8, "Schedule a new attempt for later");
        waitingForSpareQueue.push_back(call);
        if (!waitEvent) // if we add the first element
            scheduleConnectorsListCheck(); // Restart queue run
    }

    return call;
}

bool
HappyConnQueue::ConnectionsLimitRule()
{
    int limit = ConnectLimit();
    return (limit < 0 || HappyConnOpener::SpareConnects < limit);
}

bool
HappyConnQueue::GapRule()
{
    return (HappyConnOpener::LastSpareAttempt <= current_dtime - (double)ConnectGap()/1000.0);
}

int
HappyConnQueue::ConnectGap()
{
    if (Config.happyEyeballs.connect_gap < 0) // no explicit configuration
        return 5; // ms per worker

    // keep opening rate in check despite the lack of SMP sharing
    return Config.happyEyeballs.connect_gap * Config.workers;
}

int
HappyConnQueue::ConnectLimit()
{
    if (Config.happyEyeballs.connect_limit <= 0)
        return Config.happyEyeballs.connect_limit;

    int limit = Config.happyEyeballs.connect_limit / Config.workers;
    return (limit == 0 ? 1 : limit);
}

double
HappyConnQueue::spareMayStartAfter(const HappyConnOpener::Pointer &happy) const
{
    double nextAttemptTime = happy->lastAttemptTime + (double)Config.happyEyeballs.connect_timeout/1000.0;
    double mgap = (double)ConnectGap()/1000.0;
    double fromLastTry = (current_dtime - HappyConnOpener::LastSpareAttempt);
    double remainGap = mgap > fromLastTry ? mgap - fromLastTry : 0.0 ;
    double startAfter = nextAttemptTime > current_dtime ?
                        max(nextAttemptTime - current_dtime, remainGap) : remainGap;
    return startAfter;
}

bool
HappyConnQueue::primeConnectTooSlow(const HappyConnOpener::Pointer &happy) const
{
    double nextAttemptTime = happy->lastAttemptTime + (double)Config.happyEyeballs.connect_timeout/1000.0;
    return (nextAttemptTime <= current_dtime);
}

void
HappyConnQueue::SpareConnectionAttempt(void *data)
{
    HappyConnQueue *queue = static_cast<HappyConnQueue *>(data);
    queue->waitEvent = false;
    queue->scheduleConnectorsListCheck();
}

void
HappyConnQueue::scheduleConnectorsListCheck()
{
    while(!waitingForSpareQueue.empty()) {
        AsyncCall::Pointer call = waitingForSpareQueue.front();
        if (call->canceled()) {
            waitingForSpareQueue.pop_front();
            continue;
        }

        NullaryMemFunT<HappyConnOpener> *dialer = dynamic_cast<NullaryMemFunT<HappyConnOpener> *>(call->getDialer());
        assert(dialer);
        const auto he = dialer->job;
        if (!he.valid()){
            waitingForSpareQueue.pop_front();
            continue;
        }

        double startAfter = spareMayStartAfter(he);

        debugs(17, 8, "A new spare connection should start after: " << startAfter << " ms");
        if (startAfter > 0.0) {
            eventAdd("HappyConnQueue::SpareConnectionAttempt", HappyConnQueue::SpareConnectionAttempt, this, startAfter, 1, false);
            waitEvent = true;
            return; //abort here
        }

        if (ConnectionsLimitRule())
            ScheduleCallHere(call);
        else // Move to sparesLimit queue to start spare connection when a spare connection is closed
            sparesLimitQueue.push_back(call);
        waitingForSpareQueue.pop_front();
    }
}

void
HappyConnQueue::kickSparesLimitQueue()
{
    while (!sparesLimitQueue.empty() && ConnectionsLimitRule()) {
        AsyncCall::Pointer call = sparesLimitQueue.front();
        if (!call->canceled()) {
            ScheduleCallHere(call);
        }
        sparesLimitQueue.pop_front();
    }
}
