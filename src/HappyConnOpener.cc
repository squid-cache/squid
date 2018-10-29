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

// HappyOrderEnforcer optimizes enforcement of the "pause before opening a spare
// connection" requirements. Its inefficient alternative would add hundreds of
// concurrent events to the Squid event queue in many busy configurations, one
// concurrent event per concurrent HappyConnOpener job.
//
// EventScheduler::schedule() uses linear search to find the right place for a
// new event; having hundreds of concurrent events is prohibitively expensive.
// Both alternatives may have comparable high rate of eventAdd() calls, but
// HappyOrderEnforcer usually schedules the first or second event (as opposed to
// events that would be fired after hundreds of already scheduled events, making
// that linear search a lot longer).
//
// EventScheduler::cancel() also uses linear search. HappyOrderEnforcer does not
// need to cancel scheduled events, while its inefficient alternative may cancel
// events at a rate comparable to the high eventAdd() rate -- many events would
// be scheduled in vain because external factors would speed up (or make
// unnecessary) spare connection attempts, canceling the wait.
//
// This optimization is possible only where each job needs to pause for the same
// amount of time, creating a naturally ordered list of jobs waiting to be
// resumed. This is why two HappyOrderEnforcers are needed to efficiently honor
// both happy_eyeballs_connect_timeout and happy_eyeballs_connect_gap
// directives.

/// Efficiently drains a FIFO HappyConnOpener queue while delaying each "pop"
/// event by the time determined by the top element currently in the queue. Its
/// current cbdata-free implementation assumes static storage duration.
class HappyOrderEnforcer
{
public:
    /// \param aName names scheduled events, for debugging
    HappyOrderEnforcer(const char *aName): name(aName) {}

    /// resumes jobs that need resuming (if any)
    void checkpoint();

    /// starts managing the job's wait; the job should expect a call back
    void enqueue(HappyConnOpener &);

    /// stops managing the job's wait; cancels the pending callback, if any
    void dequeue(HappyConnOpener &);

    const char * const name; ///< waiting event name, for debugging

protected:
    virtual bool readyNow(const HappyConnOpener &) const = 0;
    virtual AsyncCall::Pointer notify(const CbcPointer<HappyConnOpener> &) = 0;

    bool waiting() const { return waitEnd_ > 0; }
    bool startedWaiting(const HappyAbsoluteTime lastStart, const int cfgTimeoutMsec) const;

private:
    static void NoteWaitOver(void *raw);
    void noteWaitOver();

    HappySpareWaitList jobs_; ///< queued jobs waiting their turn
    mutable HappyAbsoluteTime waitEnd_ = 0; ///< expected NoteWaitOver() call time (or zero)
};

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer)
{
    return os << answer.conn << ", " << answer.ioStatus << ", " << answer.xerrno << ", " << (answer.reused ? "reused" : "new");
}

/// enforces happy_eyeballs_connect_timeout
class PrimeChanceGiver: public HappyOrderEnforcer
{
public:
    PrimeChanceGiver(): HappyOrderEnforcer("happy_eyeballs_connect_timeout enforcement") {}

    /* HappyOrderEnforcer API */
    virtual bool readyNow(const HappyConnOpener &job) const override;

protected:
    /* HappyOrderEnforcer API */
    virtual AsyncCall::Pointer notify(const CbcPointer<HappyConnOpener> &) override;
};

/// enforces happy_eyeballs_connect_gap and happy_eyeballs_connect_limit
class SpareAllowanceGiver: public HappyOrderEnforcer
{
public:
    SpareAllowanceGiver(): HappyOrderEnforcer("happy_eyeballs_connect_gap/happy_eyeballs_connect_limit enforcement") {}

    /* HappyOrderEnforcer API */
    virtual bool readyNow(const HappyConnOpener &job) const override;

    /// reacts to HappyConnOpener discovering readyNow() conditions for a spare path
    /// the caller must attempt to open a spare connection immediately
    void jobGotInstantAllowance();

    /// reacts to HappyConnOpener getting a spare connection opening result
    void jobUsedAllowance();

    /// reacts to HappyConnOpener dropping its spare connection allowance
    void jobDroppedAllowance();

protected:
    /* HappyOrderEnforcer API */
    virtual AsyncCall::Pointer notify(const CbcPointer<HappyConnOpener> &) override;

    bool concurrencyLimitReached() const;
    void recordAllowance();
    void forgetAllowance();

    /// the time of the last noteSpareAllowance() call
    HappyAbsoluteTime lastAllowanceStart = 0;

    /// the number of noteSpareAllowance() calls not already
    /// returned via jobUsedAllowance() or jobDroppedAllowance()
    int concurrencyLevel = 0;
};

PrimeChanceGiver ThePrimeChanceGiver;
SpareAllowanceGiver TheSpareAllowanceGiver;

/* HappyOrderEnforcer */

void
HappyOrderEnforcer::enqueue(HappyConnOpener &job)
{
    Must(!job.spareWaiting.callback);
    jobs_.emplace_back(&job);
    job.spareWaiting.position = std::prev(jobs_.end());
}

void
HappyOrderEnforcer::dequeue(HappyConnOpener &job)
{
    if (job.spareWaiting.callback) {
        job.spareWaiting.callback->cancel("HappyOrderEnforcer::dequeue");
        job.spareWaiting.callback = nullptr;
    } else {
        Must(!jobs_.empty());
        jobs_.erase(job.spareWaiting.position);
    }
}

void
HappyOrderEnforcer::checkpoint()
{
    while (!jobs_.empty()) {
        if (const auto jobPtr = jobs_.front().valid()) {
            auto &job = *jobPtr;
            if (readyNow(job))
                job.spareWaiting.callback = notify(jobPtr); // and fall through to the next job
            else
                break; // the next job cannot be ready earlier (FIFO)
        }
        jobs_.pop_front();
    }
}

bool
HappyOrderEnforcer::startedWaiting(const HappyAbsoluteTime lastStart, const int cfgTimeoutMsec) const
{
    // Normally, the job would not even be queued if there is no timeout. This
    // check handles reconfiguration that happened after this job was queued.
    if (cfgTimeoutMsec <= 0)
        return false;

    // convert to seconds and adjust for SMP workers to keep aggregated load in
    // check despite the lack of coordination among workers
    const auto tout = static_cast<HappyAbsoluteTime>(cfgTimeoutMsec) * Config.workers / 1000.0;
    const auto newWaitEnd = std::min(lastStart, current_dtime) + tout;
    if (newWaitEnd <= current_dtime)
        return false; // no need to wait

    // We cannot avoid event accumulation because calling eventDelete() is
    // unsafe, but any accumulation will be small because it can only be caused
    // by hot reconfiguration changes or current time jumps.
    if (!waiting() || newWaitEnd < waitEnd_) {
        const auto waitTime = newWaitEnd - current_dtime;
        eventAdd(name, &HappyOrderEnforcer::NoteWaitOver, const_cast<HappyOrderEnforcer*>(this), waitTime, 0, false);
        waitEnd_ = newWaitEnd;
        assert(waiting());
    }

    return true;
}

void
HappyOrderEnforcer::NoteWaitOver(void *raw)
{
    assert(raw);
    static_cast<HappyOrderEnforcer*>(raw)->noteWaitOver();
}

void
HappyOrderEnforcer::noteWaitOver()
{
    Must(waiting());
    waitEnd_ = 0;
    checkpoint();
}

/* PrimeChanceGiver */

bool
PrimeChanceGiver::readyNow(const HappyConnOpener &job) const
{
    return !startedWaiting(job.primeStart, Config.happyEyeballs.connect_timeout);
}

AsyncCall::Pointer
PrimeChanceGiver::notify(const CbcPointer<HappyConnOpener> &job)
{
    return CallJobHere(17, 5, job, HappyConnOpener, noteGavePrimeItsChance);
}

/* SpareAllowanceGiver */

bool
SpareAllowanceGiver::readyNow(const HappyConnOpener &) const
{
    return !concurrencyLimitReached() &&
        !startedWaiting(lastAllowanceStart, Config.happyEyeballs.connect_gap);
}

AsyncCall::Pointer
SpareAllowanceGiver::notify(const CbcPointer<HappyConnOpener> &job)
{
    recordAllowance();
    return CallJobHere(17, 5, job, HappyConnOpener, noteSpareAllowance);
}

void
SpareAllowanceGiver::jobGotInstantAllowance()
{
    recordAllowance();
}

void
SpareAllowanceGiver::jobUsedAllowance()
{
    forgetAllowance();
}

void
SpareAllowanceGiver::jobDroppedAllowance()
{
    // Without happy_eyeballs_connect_gap, lastAllowanceStart does not matter.
    // Otherwise, the dropped allowance ought to be the last one, and since it
    // was allowed, we would still observe the gap even if we do not wait now.
    lastAllowanceStart = 0;

    forgetAllowance();
}

/// account for the given allowance
void
SpareAllowanceGiver::recordAllowance()
{
    ++concurrencyLevel;
    lastAllowanceStart = current_dtime;
    // not a checkpoint(): no other spare can become ready here
}

void
SpareAllowanceGiver::forgetAllowance()
{
    Must(concurrencyLevel);
    --concurrencyLevel;
    checkpoint();
}

/// whether opening a spare connection now would violate happy_eyeballs_connect_limit
bool
SpareAllowanceGiver::concurrencyLimitReached() const
{
    if (Config.happyEyeballs.connect_limit < 0)
        return false; // no limit

    if (Config.happyEyeballs.connect_limit == 0)
        return true; // concurrent spares prohibited regardless of spare level

    // adjust for SMP workers to keep aggregated spare level in check despite
    // the lack of coordination among workers
    const auto aggregateLevel = concurrencyLevel * Config.workers;
    return aggregateLevel >= Config.happyEyeballs.connect_limit;
}

/* HappyConnOpener */

HappyConnOpener::HappyConnOpener(const ResolvedPeers::Pointer &destinations, const AsyncCall::Pointer &aCall, const time_t aFwdStart, int tries):
    AsyncJob("HappyConnOpener"),
    useTos(0),
    useNfmark(0),
    maxTries(tries),
    fwdStart(aFwdStart),
    callback_(aCall),
    dests_(destinations),
    allowPconn_(true),
    retriable_(true),
    host_(nullptr),
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
    dests_->updateNotificationPending = false;
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

    if (spareWaiting)
        cancelSpareWait("HappyConnOpener object destructed");

    // TODO: These call cancellations should not be needed.

    if (prime.path) {
        if (prime.connector)
            prime.connector->cancel("HappyConnOpener object destructed");
        prime.connector = nullptr;
        prime.path = nullptr;
    }

    if (spare.path) {
        if (spare.connector)
            spare.connector->cancel("HappyConnOpener object destructed");
        spare.connector = nullptr;
        spare.path = nullptr;
        if (gotSpareAllowance) {
            TheSpareAllowanceGiver.jobDroppedAllowance();
            gotSpareAllowance = false;
        }
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
    dests_->updateNotificationPending = false;
    checkForNewConnection();
}

/// starts opening (or reusing) a connection to the given destination
void
HappyConnOpener::startConnecting(PendingConnection &attempt, Comm::ConnectionPointer &dest)
{
    Must(!attempt.path);
    Must(!attempt.connector);
    Must(dest);

    if (!allowPconn_ || !reuseOldConnection(attempt, dest))
        openFreshConnection(attempt, dest);
}

/// reuses a persistent connection to the given destination (if possible)
/// \returns true if and only if reuse was possible
/// must be called via startConnecting()
bool
HappyConnOpener::reuseOldConnection(PendingConnection &attempt, Comm::ConnectionPointer &dest)
{
    assert(allowPconn_);

    const auto pconn = PconnPop(dest, (dest->getPeer() ? nullptr : host_), retriable_);
    if (!Comm::IsConnOpen(pconn))
        return false;

    attempt.path = pconn;
    attempt.connector = nullptr;
    ++n_tries;
    callCallback(pconn, Comm::OK, 0, true, "reusing pconn");
    return true;
}

/// opens a fresh connection to the given destination
/// must be called via startConnecting()
void
HappyConnOpener::openFreshConnection(PendingConnection &attempt, Comm::ConnectionPointer &dest)
{
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
    const time_t connTimeout = dest->connectTimeout(fwdStart);
    Comm::ConnOpener *cs = new Comm::ConnOpener(dest, callConnect, connTimeout);
    if (!dest->getPeer())
        cs->setHost(host_);

    attempt.path = dest;
    attempt.connector = callConnect;

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
        if (gotSpareAllowance) {
            TheSpareAllowanceGiver.jobUsedAllowance();
            gotSpareAllowance = false;
        }
    }

    if (params.flag == Comm::OK) {
        callCallback(params.conn, Comm::OK, 0, false, what);
        return;
    }

    debugs(17, 8, what << " failed: " << params.conn);
    if (const auto peer = params.conn->getPeer())
        peerConnectFailed(peer);
    params.conn->close(); // TODO: Comm::ConnOpener should do this instead.

    if (spareWaiting)
        updateSpareWaitAfterPrimeFailure();

    checkForNewConnection();
}

/// reacts to a prime attempt failure
void
HappyConnOpener::updateSpareWaitAfterPrimeFailure()
{
    Must(currentPeer);
    Must(!prime);
    Must(spareWaiting);

    if (dests_->doneWithPrimes(*currentPeer)) {
        cancelSpareWait("all primes failed");
        ignoreSpareRestrictions = true;
        return; // checkForNewConnection() will open a spare connection ASAP
    }

    if (spareWaiting.toGivePrimeItsChance)
        stopGivingPrimeItsChance();

    // may still be spareWaiting.forSpareAllowance or
    // may still be spareWaiting.forPrimesToFail
}

void
HappyConnOpener::stopGivingPrimeItsChance() {
    Must(spareWaiting.toGivePrimeItsChance);
    spareWaiting.toGivePrimeItsChance = false;
    ThePrimeChanceGiver.dequeue(*this);
}

void
HappyConnOpener::stopWaitingForSpareAllowance() {
    Must(spareWaiting.forSpareAllowance);
    spareWaiting.forSpareAllowance = false;

    if (spareWaiting.callback)
        TheSpareAllowanceGiver.jobDroppedAllowance();
    TheSpareAllowanceGiver.dequeue(*this); // clears spareWaiting.callback
}

/// stops waiting for the right conditions to open a spare connection
void
HappyConnOpener::cancelSpareWait(const char *reason)
{
    debugs(17, 5, "because " << reason);
    Must(spareWaiting);

    if (spareWaiting.toGivePrimeItsChance)
        stopGivingPrimeItsChance();
    else if (spareWaiting.forSpareAllowance)
        stopWaitingForSpareAllowance();

    spareWaiting.clear();
}

/** Called when an external event changes dests_, prime, spare, or spareWaiting.
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

    // update stale currentPeer and/or stale spareWaiting
    if (currentPeer && !spare && !prime && dests_->doneWithPeer(*currentPeer)) {
        debugs(17, 7, "done with peer; " << *currentPeer);
        if (spareWaiting.forNewPeer)
            cancelSpareWait("done with peer");
        else
            Must(!spareWaiting);

        currentPeer = nullptr;
        ignoreSpareRestrictions = false;
        Must(!gotSpareAllowance);
    } else if (currentPeer && !spareWaiting.forNewPeer && spareWaiting && dests_->doneWithSpares(*currentPeer)) {
        cancelSpareWait("no spares are coming");
        spareWaiting.forNewPeer = true;
    }

    // open a new prime and/or a new spare connection if needed
    if (!dests_->empty()) {
        if (!currentPeer) {
            currentPeer = dests_->extractFront();
            Must(currentPeer);
            debugs(17, 7, "new peer " << *currentPeer);
            primeStart = current_dtime;
            startConnecting(prime, currentPeer);
            maybeGivePrimeItsChance();
            Must(prime); // entering state #1.1
        } else {
            if (!prime)
                maybeOpenAnotherPrimeConnection(); // may make dests_ empty()
        }

        if (!spare && !spareWaiting)
            maybeOpenSpareConnection(); // may make dests_ empty()

        Must(currentPeer);
    }

    if (currentPeer) {
        debugs(17, 7, "working on " << *currentPeer);
        return; // remaining in state #1.1 or #1.2
    }

    if (!dests_->destinationsFinalized) {
        debugs(17, 7, "waiting for more peers");
        return; // remaining in state #2
    }

    debugs(17, 7, "done; no more peers");
    Must(doneAll());
    // entering state #3
}

/// called after happy_eyeballs_connect_timeout expires
void
HappyConnOpener::noteGavePrimeItsChance()
{
    Must(spareWaiting.toGivePrimeItsChance);
    spareWaiting.clear();
    checkForNewConnection();
}

void
HappyConnOpener::noteSpareAllowance()
{
    Must(spareWaiting.forSpareAllowance);
    spareWaiting.clear();
    Must(!gotSpareAllowance);
    gotSpareAllowance = true;
    auto dest = dests_->extractSpare(*currentPeer); // ought to succeed
    startConnecting(spare, dest);
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
    if (auto dest = dests_->extractPrime(*currentPeer))
        startConnecting(prime, dest);
    // else wait for more prime paths or their exhaustion
}

/// starts waiting for a spare permission (if spare connections may be possible)
/// or does nothing (otherwise)
void
HappyConnOpener::maybeGivePrimeItsChance()
{
    Must(currentPeer);
    Must(prime);
    Must(!spare);
    Must(!spareWaiting);

    if (dests_->doneWithSpares(*currentPeer)) {
        debugs(17, 7, "no spares for " << *currentPeer);
        spareWaiting.forNewPeer = true;
        return;
    }

    if (Config.happyEyeballs.connect_limit == 0) {
        debugs(17, 7, "concurrent spares are prohibited");
        spareWaiting.forPrimesToFail = true;
        return;
    }

    if (ThePrimeChanceGiver.readyNow(*this)) {
        debugs(17, 7, "no happy_eyeballs_connect_timeout");
        return;
    }

    ThePrimeChanceGiver.enqueue(*this);
    spareWaiting.toGivePrimeItsChance = true;
    // wait for a prime connect result or noteGavePrimeItsChance()
}

/// if possible, starts a spare connection attempt, returning true
bool
HappyConnOpener::maybeOpenSpareConnection()
{
    Must(currentPeer);
    Must(!spare);
    Must(!spareWaiting);
    Must(!gotSpareAllowance);

    // jobGotInstantAllowance() call conditions below rely on the readyNow() check here
    if (!ignoreSpareRestrictions && // we have to honor spare restrictions
        !TheSpareAllowanceGiver.readyNow(*this) && // all new spares must wait
        dests_->haveSpare(*currentPeer)) { // and we do have a new spare
        TheSpareAllowanceGiver.enqueue(*this);
        spareWaiting.forSpareAllowance = true;
        return false;
    }

    if (auto dest = dests_->extractSpare(*currentPeer)) {

        if (!ignoreSpareRestrictions) {
            TheSpareAllowanceGiver.jobGotInstantAllowance();
            gotSpareAllowance = true;
        }

        startConnecting(spare, dest);
        return true;
    }
    // else wait for more spare paths or their exhaustion
    return false;
}
