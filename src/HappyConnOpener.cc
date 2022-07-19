/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "base/CodeContext.h"
#include "CachePeer.h"
#include "errorpage.h"
#include "FwdState.h"
#include "HappyConnOpener.h"
#include "HttpRequest.h"
#include "ip/QosConfig.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(HappyConnOpener);

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

std::ostream &operator <<(std::ostream &os, const HappyConnOpenerAnswer &answer)
{
    if (answer.error.set())
        os << "bad ";
    if (answer.conn)
        os << (answer.reused ? "reused " : "new ") << answer.conn;
    if (answer.n_tries != 1)
        os << " after " << answer.n_tries;
    return os;
}

/// enforces happy_eyeballs_connect_timeout
class PrimeChanceGiver: public HappyOrderEnforcer
{
public:
    PrimeChanceGiver(): HappyOrderEnforcer("happy_eyeballs_connect_timeout enforcement") {}

    /* HappyOrderEnforcer API */
    virtual bool readyNow(const HappyConnOpener &job) const override;

private:
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

private:
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
    job.spareWaiting.codeContext = CodeContext::Current();
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
            if (!readyNow(job))
                break; // the next job cannot be ready earlier (FIFO)
            CallBack(job.spareWaiting.codeContext, [&] {
                job.spareWaiting.callback = notify(jobPtr); // and fall through to the next job
            });
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

/* HappyConnOpenerAnswer */

HappyConnOpenerAnswer::~HappyConnOpenerAnswer()
{
    // XXX: When multiple copies of an answer exist, this delete in one copy
    // invalidates error in other copies -- their error.get() returns nil. The
    // current code "works", but probably only because the initiator gets the
    // error before any answer copies are deleted. Same in ~EncryptorAnswer.
    delete error.get();
}

/* HappyConnOpener */

HappyConnOpener::HappyConnOpener(const ResolvedPeers::Pointer &dests, const AsyncCall::Pointer &aCall, HttpRequest::Pointer &request, const time_t aFwdStart, int tries, const AccessLogEntry::Pointer &anAle):
    AsyncJob("HappyConnOpener"),
    fwdStart(aFwdStart),
    callback_(aCall),
    destinations(dests),
    prime(&HappyConnOpener::notePrimeConnectDone, "HappyConnOpener::notePrimeConnectDone"),
    spare(&HappyConnOpener::noteSpareConnectDone, "HappyConnOpener::noteSpareConnectDone"),
    ale(anAle),
    cause(request),
    n_tries(tries)
{
    assert(destinations);
    assert(dynamic_cast<Answer*>(callback_->getDialer()));
}

HappyConnOpener::~HappyConnOpener()
{
    safe_free(host_);
    delete lastError;
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
    destinations->notificationPending = false;
    checkForNewConnection();
}

bool
HappyConnOpener::doneAll() const
{
    if (!callback_)
        return true; // (probably found a good path and) informed the requestor

    // TODO: Expose AsyncCall::canFire() instead so that code like this can
    // detect gone initiators without the need to explicitly cancel callbacks.
    if (callback_->canceled())
        return true; // the requestor is gone or has lost interest

    if (prime || spare)
        return false;

    if (ranOutOfTimeOrAttempts())
        return true; // trying new connection paths prohibited

    if (destinations->empty() && destinations->destinationsFinalized)
        return true; // there are no more paths to try

    return false;
}

void
HappyConnOpener::swanSong()
{
    debugs(17, 5, this);

    if (callback_ && !callback_->canceled())
        sendFailure();

    if (spareWaiting)
        cancelSpareWait("HappyConnOpener object destructed");

    // TODO: Find an automated, faster way to kill no-longer-needed jobs.

    if (prime) {
        cancelAttempt(prime, "job finished during a prime attempt");
    }

    if (spare) {
        cancelAttempt(spare, "job finished during a spare attempt");
        if (gotSpareAllowance) {
            TheSpareAllowanceGiver.jobDroppedAllowance();
            gotSpareAllowance = false;
        }
    }

    AsyncJob::swanSong();
}

/// HappyConnOpener::Attempt printer for debugging
std::ostream &
operator <<(std::ostream &os, const HappyConnOpener::Attempt &attempt)
{
    if (!attempt.path)
        os << '-';
    else if (attempt.path->isOpen())
        os << "FD " << attempt.path->fd;
    else if (attempt.connWait)
        os << attempt.connWait;
    else // destination is known; connection closed (and we are not opening any)
        os << attempt.path->id;
    return os;
}

const char *
HappyConnOpener::status() const
{
    // TODO: In a redesigned status() API, the caller may mimic this approach.
    static SBuf buf;
    buf.clear();

    SBufStream os(buf);

    os.write(" [", 2);
    if (stopReason)
        os << "Stopped:" << stopReason;
    if (prime)
        os << "prime:" << prime;
    if (spare)
        os << "spare:" << spare;
    if (n_tries)
        os << " tries:" << n_tries;
    os << ' ' << id << ']';

    buf = os.buf();
    return buf.c_str();
}

/// Create "503 Service Unavailable" or "504 Gateway Timeout" error depending
/// on whether this is a validation request. RFC 7234 section 5.2.2 says that
/// we MUST reply with "504 Gateway Timeout" if validation fails and cached
/// reply has proxy-revalidate, must-revalidate or s-maxage Cache-Control
/// directive.
ErrorState *
HappyConnOpener::makeError(const err_type type) const
{
    const auto statusCode = cause->flags.needValidation ?
                            Http::scGatewayTimeout : Http::scServiceUnavailable;
    return new ErrorState(type, statusCode, cause.getRaw(), ale);
}

/// \returns pre-filled Answer if the initiator needs an answer (or nil)
HappyConnOpener::Answer *
HappyConnOpener::futureAnswer(const PeerConnectionPointer &conn)
{
    if (callback_ && !callback_->canceled()) {
        const auto answer = dynamic_cast<Answer *>(callback_->getDialer());
        assert(answer);
        answer->conn = conn;
        answer->n_tries = n_tries;
        return answer;
    }
    return nullptr;
}

/// send a successful result to the initiator (if it still needs an answer)
void
HappyConnOpener::sendSuccess(const PeerConnectionPointer &conn, const bool reused, const char *connKind)
{
    debugs(17, 4, connKind << ": " << conn);
    if (auto *answer = futureAnswer(conn)) {
        answer->reused = reused;
        assert(!answer->error);
        ScheduleCallHere(callback_);
    }
    callback_ = nullptr;
}

/// cancels the in-progress attempt, making its path a future candidate
void
HappyConnOpener::cancelAttempt(Attempt &attempt, const char *reason)
{
    Must(attempt);
    destinations->reinstatePath(attempt.path); // before attempt.cancel() clears path
    attempt.cancel(reason);
}

/// inform the initiator about our failure to connect (if needed)
void
HappyConnOpener::sendFailure()
{
    debugs(17, 3, lastFailedConnection);
    if (auto *answer = futureAnswer(lastFailedConnection)) {
        if (!lastError)
            lastError = makeError(ERR_GATEWAY_FAILURE);
        answer->error = lastError;
        assert(answer->error.valid());
        lastError = nullptr; // the answer owns it now
        ScheduleCallHere(callback_);
    }
    callback_ = nullptr;
}

void
HappyConnOpener::noteCandidatesChange()
{
    destinations->notificationPending = false;
    checkForNewConnection();
}

/// starts opening (or reusing) a connection to the given destination
void
HappyConnOpener::startConnecting(Attempt &attempt, PeerConnectionPointer &dest)
{
    Must(!attempt.path);
    Must(!attempt.connWait);
    Must(dest);

    const auto bumpThroughPeer = cause->flags.sslBumped && dest->getPeer();
    const auto canReuseOld = allowPconn_ && !bumpThroughPeer;
    if (!canReuseOld || !reuseOldConnection(dest))
        openFreshConnection(attempt, dest);
}

/// reuses a persistent connection to the given destination (if possible)
/// \returns true if and only if reuse was possible
/// must be called via startConnecting()
bool
HappyConnOpener::reuseOldConnection(PeerConnectionPointer &dest)
{
    assert(allowPconn_);

    if (const auto pconn = fwdPconnPool->pop(dest, host_, retriable_)) {
        ++n_tries;
        dest.finalize(pconn);
        sendSuccess(dest, true, "reused connection");
        return true;
    }

    return false;
}

/// opens a fresh connection to the given destination
/// must be called via startConnecting()
void
HappyConnOpener::openFreshConnection(Attempt &attempt, PeerConnectionPointer &dest)
{
#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    const auto conn = dest->cloneProfile();
    GetMarkingsToServer(cause.getRaw(), *conn);

    typedef CommCbMemFunT<HappyConnOpener, CommConnectCbParams> Dialer;
    AsyncCall::Pointer callConnect = asyncCall(48, 5, attempt.callbackMethodName,
                                     Dialer(this, attempt.callbackMethod));
    const time_t connTimeout = dest->connectTimeout(fwdStart);
    auto cs = new Comm::ConnOpener(conn, callConnect, connTimeout);
    if (!conn->getPeer())
        cs->setHost(host_);

    attempt.path = dest; // but not the being-opened conn!
    attempt.connWait.start(cs, callConnect);
}

/// Comm::ConnOpener callback for the prime connection attempt
void
HappyConnOpener::notePrimeConnectDone(const CommConnectCbParams &params)
{
    handleConnOpenerAnswer(prime, params, "new prime connection");
}

/// Comm::ConnOpener callback for the spare connection attempt
void
HappyConnOpener::noteSpareConnectDone(const CommConnectCbParams &params)
{
    if (gotSpareAllowance) {
        TheSpareAllowanceGiver.jobUsedAllowance();
        gotSpareAllowance = false;
    }
    handleConnOpenerAnswer(spare, params, "new spare connection");
}

/// prime/spare-agnostic processing of a Comm::ConnOpener result
void
HappyConnOpener::handleConnOpenerAnswer(Attempt &attempt, const CommConnectCbParams &params, const char *what)
{
    Must(params.conn);

    // finalize the previously selected path before attempt.finish() forgets it
    auto handledPath = attempt.path;
    handledPath.finalize(params.conn); // closed on errors
    attempt.finish();

    ++n_tries;

    if (params.flag == Comm::OK) {
        sendSuccess(handledPath, false, what);
        return;
    }

    debugs(17, 8, what << " failed: " << params.conn);
    if (const auto peer = params.conn->getPeer())
        peerConnectFailed(peer);

    // remember the last failure (we forward it if we cannot connect anywhere)
    lastFailedConnection = handledPath;
    delete lastError;
    lastError = nullptr; // in case makeError() throws
    lastError = makeError(ERR_CONNECT_FAIL);
    lastError->xerrno = params.xerrno;

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

    if (destinations->doneWithPrimes(*currentPeer)) {
        cancelSpareWait("all primes failed");
        ignoreSpareRestrictions = true;
        return; // checkForNewConnection() will open a spare connection ASAP
    }

    if (spareWaiting.toGivePrimeItsChance)
        stopGivingPrimeItsChance();

    // may still be spareWaiting.forSpareAllowance or
    // may still be spareWaiting.forPrimesToFail
}

/// called when the prime attempt has used up its chance for a solo victory
void
HappyConnOpener::stopGivingPrimeItsChance() {
    Must(spareWaiting.toGivePrimeItsChance);
    spareWaiting.toGivePrimeItsChance = false;
    ThePrimeChanceGiver.dequeue(*this);
}

/// called when the spare attempt should no longer obey spare connection limits
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

/** Called when an external event changes initiator interest, destinations,
 * prime, spare, or spareWaiting. Leaves HappyConnOpener in one of these
 * (mutually exclusive beyond the exceptional state #0) "stable" states:
 *
 * 0. Exceptional termination: done()
 * 1. Processing a single peer: currentPeer
 *    1.1. Connecting: prime || spare
 *    1.2. Waiting for spare gap and/or paths: !prime && !spare
 * 2. Waiting for a new peer: destinations->empty() && !destinations->destinationsFinalized && !currentPeer
 * 3. Finished: destinations->empty() && destinations->destinationsFinalized && !currentPeer
 */
void
HappyConnOpener::checkForNewConnection()
{
    debugs(17, 7, *destinations);

    // The order of the top-level if-statements below is important.

    if (done())
        return; // bail ASAP to minimize our waste and others delays (state #0)

    if (ranOutOfTimeOrAttempts()) {
        Must(currentPeer); // or we would be done() already
        return; // will continue working (state #1.1)
    }

    // update stale currentPeer and/or stale spareWaiting
    if (currentPeer && !spare && !prime && destinations->doneWithPeer(*currentPeer)) {
        debugs(17, 7, "done with peer; " << *currentPeer);
        if (spareWaiting.forNewPeer)
            cancelSpareWait("done with peer");
        else
            Must(!spareWaiting);

        currentPeer = nullptr;
        ignoreSpareRestrictions = false;
        Must(!gotSpareAllowance);
    } else if (currentPeer && !spareWaiting.forNewPeer && spareWaiting && destinations->doneWithSpares(*currentPeer)) {
        cancelSpareWait("no spares are coming");
        spareWaiting.forNewPeer = true;
    }

    // open a new prime and/or a new spare connection if needed
    if (!destinations->empty()) {
        if (!currentPeer) {
            auto newPrime = destinations->extractFront();
            currentPeer = newPrime;
            Must(currentPeer);
            debugs(17, 7, "new peer " << *currentPeer);
            primeStart = current_dtime;
            startConnecting(prime, newPrime);
            // TODO: if reuseOldConnection() in startConnecting() above succeeds,
            // then we should not get here, and Must(prime) below will fail.
            maybeGivePrimeItsChance();
            Must(prime); // entering state #1.1
        } else {
            if (!prime)
                maybeOpenAnotherPrimeConnection(); // may make destinations empty()
        }

        if (!spare && !spareWaiting)
            maybeOpenSpareConnection(); // may make destinations empty()

        Must(currentPeer);
    }

    if (currentPeer) {
        debugs(17, 7, "working on " << *currentPeer);
        return; // remaining in state #1.1 or #1.2
    }

    if (!destinations->destinationsFinalized) {
        debugs(17, 7, "waiting for more peers");
        return; // remaining in state #2
    }

    debugs(17, 7, "done; no more peers");
    Must(doneAll());
    // entering state #3
}

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

    if (ranOutOfTimeOrAttempts()) {
        TheSpareAllowanceGiver.jobDroppedAllowance();
        return; // will quit or continue working on prime
    }

    Must(!gotSpareAllowance);
    gotSpareAllowance = true;

    auto dest = destinations->extractSpare(*currentPeer); // ought to succeed
    startConnecting(spare, dest);
}

/// starts a prime connection attempt if possible or does nothing otherwise
void
HappyConnOpener::maybeOpenAnotherPrimeConnection()
{
    Must(currentPeer);
    if (auto dest = destinations->extractPrime(*currentPeer))
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

    if (destinations->doneWithSpares(*currentPeer)) {
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

/// if possible, starts a spare connection attempt
void
HappyConnOpener::maybeOpenSpareConnection()
{
    Must(currentPeer);
    Must(!spare);
    Must(!spareWaiting);
    Must(!gotSpareAllowance);

    if (ranOutOfTimeOrAttempts())
        return; // will quit or continue working on prime

    // jobGotInstantAllowance() call conditions below rely on the readyNow() check here
    if (!ignoreSpareRestrictions && // we have to honor spare restrictions
            !TheSpareAllowanceGiver.readyNow(*this) && // all new spares must wait
            destinations->haveSpare(*currentPeer)) { // and we do have a new spare
        TheSpareAllowanceGiver.enqueue(*this);
        spareWaiting.forSpareAllowance = true;
        return;
    }

    if (auto dest = destinations->extractSpare(*currentPeer)) {

        if (!ignoreSpareRestrictions) {
            TheSpareAllowanceGiver.jobGotInstantAllowance();
            gotSpareAllowance = true;
        }

        startConnecting(spare, dest);
        return;
    }

    // wait for more spare paths or their exhaustion
}

/// Check for maximum connection tries and forwarding time restrictions
bool
HappyConnOpener::ranOutOfTimeOrAttempts() const
{
    if (ranOutOfTimeOrAttemptsEarlier_)
        return true;

    if (n_tries >= Config.forward_max_tries) {
        debugs(17, 5, "maximum allowed tries exhausted");
        ranOutOfTimeOrAttemptsEarlier_ = "maximum tries";
        return true;
    }

    if (FwdState::ForwardTimeout(fwdStart) <= 0) {
        debugs(17, 5, "forwarding timeout");
        ranOutOfTimeOrAttemptsEarlier_ = "forwarding timeout";
        return true;
    }

    return false;
}

HappyConnOpener::Attempt::Attempt(const CallbackMethod method, const char *methodName):
    callbackMethod(method),
    callbackMethodName(methodName)
{
}

void
HappyConnOpener::Attempt::finish()
{
    connWait.finish();
    path = nullptr;
}

void
HappyConnOpener::Attempt::cancel(const char *reason)
{
    connWait.cancel(reason);
    path = nullptr;
}

