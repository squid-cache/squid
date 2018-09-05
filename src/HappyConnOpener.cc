#include "squid.h"
#include "CachePeer.h"
#include "FwdState.h"
#include "HappyConnOpener.h"
#include "HttpRequest.h"
#include "ip/QosConfig.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
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
    bool primaryConnectTooSlow(const HappyConnOpener::Pointer &happy) const;

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

HappyConnOpener::HappyConnOpener(const CandidatePaths::Pointer &destinations, const AsyncCall::Pointer &aCall, const time_t fwdStart, int tries) : AsyncJob("HappyConnOpener"), useTos(0), useNfmark(0), callback_(aCall), dests_(destinations), allowPconn_(true), retriable_(true), host_(nullptr), fwdStart_(fwdStart), maxTries(tries), n_tries(0)
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
    if (!callback_ || callback_->canceled())
        return AsyncJob::doneAll();
    return false;
}

void
HappyConnOpener::swanSong()
{
    debugs(17,5, "HappyConnOpener::swanSong: Job finished, cleanup");
    if (callback_) {
        callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "unexpected end");
    }

    // TODO: These call cancellations should not be needed.
    if (activeSpareCall)
        activeSpareCall->cancel("HappyConnOpener object destructed");

    if (master.path) {
        if (master.connector)
            master.connector->cancel("HappyConnOpener object destructed");
        master.connector = nullptr;
        master.path = nullptr;
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

void
HappyConnOpener::startConnecting(PendingConnection &pconn, Comm::ConnectionPointer &dest)
{
    assert(!spare.path);
    assert(!spare.connector);
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
    // XXX: Some of this logic is wrong: If a master connection failed, and we
    // do not have any spare paths to try, but we do have another master-family,
    // same-peer path to try, then we should do another master attempt while
    // preserving the activeSpareCall wait.
    // Test case: a4.down4.up4.a6.happy.test

    if (activeSpareCall) {
        // If we are waiting to start a new spare, then cancel because we are
        // going to schedule a new spare connection attempt if required.
        // TODO: Cancel unconditionally.
        if (!activeSpareCall->canceled())
            activeSpareCall->cancel("outdated");
        activeSpareCall = nullptr;
    }

    if (master.path == params.conn) {
        // master connection is now the remaining spare if exist, or null
        master = spare;
    } else {
        assert(spare.path == params.conn);
    }

    if (spare.path) {
        --SpareConnects;
        spare.path = nullptr;
        spare.connector = nullptr;
        // trigger the HappyQueue
        HappyQueue.kickSparesLimitQueue();
    }

    if (params.flag != Comm::OK) {
        debugs(17, 8, "Connections to " << params.conn << " failed");
        /* it might have been a timeout with a partially open link */
        if (params.conn != NULL) {
            if (params.conn->getPeer())
                peerConnectFailed(params.conn->getPeer());

            params.conn->close();
        }

        checkForNewConnection();
        return;
    }

    debugs(17, 8, "Connections to " << params.conn << " succeed");
    if (master.path) {
        Must(master.connector);
        master.connector->cancel("Already connected");
        master.connector = nullptr;
        master.path = nullptr;
    }

    callCallback(params.conn, Comm::OK, 0, false, "new connection");
    return;
}

/// \returns usable master path (if possible) or nil (on failures)
/// reports permanent failures to the job initiator
Comm::ConnectionPointer
HappyConnOpener::extractMasterCandidatePath()
{
    if (!dests_->empty())
        return dests_->popFirst(); // found one

    if (!dests_->destinationsFinalized)
        return Comm::ConnectionPointer(); // may get one later

    /* permanent failure */
    callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "Found no usable destinations");
    return Comm::ConnectionPointer();
}

/// returns usable spare path (if possible) or nil (on temporary failures)
/// no failures can be permanent -- there is an ongoing master attempt
Comm::ConnectionPointer
HappyConnOpener::extractSpareCandidatePath()
{
    Must(master);
    // TODO: Rename/rafactor to popSamePeerDifferentFamily(master.path)
    return dests_->popFirstFromDifferentFamily(
        master.path->getPeer(),
        CandidatePaths::ConnectionFamily(master.path));
}

void
HappyConnOpener::checkForNewConnection()
{
    assert(dests_); // TODO: remove this and others
    debugs(17, 7, "destinations: " << dests_->size() << " finalized: " << dests_->destinationsFinalized);

    if (!master)
        return ensureMasterConnection();

    if (!spare)
        return ensureSpareConnection();
}

// XXX: Describe.
void
HappyConnOpener::resumeSpareAttempt()
{
    activeSpareCall = nullptr;
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

/// if possible, starts a master connection attempt
/// otherwise, either waits for more candidates or ends the job, as appropriate
void
HappyConnOpener::ensureMasterConnection()
{
    Must(!spare); // or that spare should have become master

    auto dest = extractMasterCandidatePath();
    if (!dest)
        return; // extractMasterCandidatePath() handles extraction failures

    debugs(17, 8, "to " << *dest);
    startConnecting(master, dest);

    if (activeSpareCall) {
        // This happens if a master connection fails while there is another
        // same-family, same-peer path available and no spare paths available.
        // Test case: a4.down4.up4.a6.happy.test
        debugs(17, 7, "already waiting for spare: " << activeSpareCall);
        return;
    }

    // TODO: Find a way to move this check into HappyQueue?
    if (dests_->empty() && dests_->destinationsFinalized) {
        debugs(17, 7, "no spare paths expected");
        return; // this is not a failure -- we are master-connecting
    }
    // TODO: Rename to waitForSpareOpportunity
    activeSpareCall = HappyQueue.queueASpareConnection(HappyConnOpener::Pointer(this));
}

/// if possible, starts a spare connection attempt
/// otherwise, waits for more candidates and/or spare connection allowance
void
HappyConnOpener::ensureSpareConnection()
{
    Must(master); // or we should be starting a master connection instead

    // TODO: Cancel wait if no spare candidates are going to be available?

    // TODO: Rename to waitingForSpareGap or something like that
    if (activeSpareCall)
        return; // honor spare connection gap

    auto dest = extractSpareCandidatePath();
    if (!dest)
        return;

    debugs(17, 8, "to " << *dest);
    startConnecting(spare, dest);

    // TODO: Check (and explain) why only the new attempts should count.
    if (spare.connector != nullptr) { // this is a new connection attempt
        ++SpareConnects;
        LastSpareAttempt = current_dtime;
    }
}

AsyncCall::Pointer
HappyConnQueue::queueASpareConnection(HappyConnOpener::Pointer happy)
{
    if (ConnectLimit() == 0) {
        debugs(17, 8, "Spare connections are disabled");
        static AsyncCall::Pointer nil;
        return nil;
    }

    bool needsSpareNow = primaryConnectTooSlow(happy);
    bool gapRuleOK = GapRule();
    bool connectionsLimitRuleOK = ConnectionsLimitRule();
    bool startSpareNow = happy->sparesBlockedOnCandidatePaths ||
                         (needsSpareNow && gapRuleOK && connectionsLimitRuleOK);

    typedef NullaryMemFunT<HappyConnOpener> Dialer;
    AsyncCall::Pointer call = JobCallback(17, 5, Dialer, happy, HappyConnOpener::resumeSpareAttempt);
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
HappyConnQueue::primaryConnectTooSlow(const HappyConnOpener::Pointer &happy) const
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
