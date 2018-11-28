/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HAPPYCONNOPENER_H
#define SQUID_HAPPYCONNOPENER_H
#include "base/RefCount.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "http/forward.h"

class FwdState;
class HappyConnOpener;
class HappyOrderEnforcer;
class JobGapEnforcer;
class ResolvedPeers;
typedef RefCount<ResolvedPeers> ResolvedPeersPointer;

/// A FIFO queue of HappyConnOpener jobs waiting to open a spare connection.
typedef std::list< CbcPointer<HappyConnOpener> > HappySpareWaitList;

/// absolute time in fractional seconds; compatible with current_timed
typedef double HappyAbsoluteTime;

/// keeps track of HappyConnOpener spare track waiting state
class HappySpareWait {
public:
    explicit operator bool() const { return toGivePrimeItsChance || forSpareAllowance || forPrimesToFail || forNewPeer; }

    /// restores default-constructed state
    /// nullifies but does not cancel the callback
    void clear() { *this = HappySpareWait(); }

    /// a pending noteGavePrimeItsChance() or noteSpareAllowance() call
    AsyncCall::Pointer callback;

    /// location on the toGivePrimeItsChance or forSpareAllowance wait list
    /// invalidated when the callback is set
    HappySpareWaitList::iterator position;

    /* The following four fields represent mutually exclusive wait reasons. */

    /// Honoring happy_eyeballs_connect_timeout (once per currentPeer).
    /// A prime connection failure ends this wait.
    bool toGivePrimeItsChance = false;

    /// Honors happy_eyeballs_connect_gap and positive happy_eyeballs_connect_limit
    /// (one allowance per spare path).
    /// Does not start until there is a new spare path to try.
    /// Prime exhaustion ends this wait (see ignoreSpareRestrictions).
    bool forSpareAllowance = false;

    /// Honors zero happy_eyeballs_connect_limit.
    /// Prime exhaustion ends this wait (see ignoreSpareRestrictions).
    bool forPrimesToFail = false;

    /// The current peer has no spares left to try.
    /// Prime exhaustion ends this wait (by changing currentPeer).
    bool forNewPeer = false;
};

/// Final result (an open connection or an error) sent to the job initiator.
class HappyConnOpenerAnswer
{
public:
    Comm::ConnectionPointer conn; ///< The last tried connection
    Comm::Flag ioStatus = Comm::OK; ///< The last tried connection status
    const char *host = nullptr; ///< The connected host. Used by pinned connections
    int xerrno = 0; ///< The system error
    const char *status = nullptr; ///< A status message for debugging reasons
    bool reused = false; ///< True if this is a reused connection
    int n_tries = 0; ///< The number of connection tries

    friend std::ostream &operator <<(std::ostream &os, const HappyConnOpenerAnswer &answer);
};

/// A TCP connection opening algorithm based on Happy Eyeballs (RFC 8305).
/// Maintains two concurrent connection opening tracks: prime and spare.
/// Shares ResolvedPeers list with the job initiator.
class HappyConnOpener: public AsyncJob
{
    CBDATA_CLASS(HappyConnOpener);
public:
    typedef HappyConnOpenerAnswer Answer;

    /// A callback dialer for setting the Answer.
    class CbDialer: public CallDialer {
    public:
        typedef void (FwdState::*Method)(const HappyConnOpener::Answer &);

        virtual ~CbDialer() {}
        CbDialer(Method method, FwdState *fwd): method_(method), fwd_(fwd) {}

        /* CallDialer API */
        virtual bool canDial(AsyncCall &call) {return fwd_.valid();};
        virtual void dial(AsyncCall &call) {((&(*fwd_))->*method_)(answer_);};
        virtual void print(std::ostream &os) const {
            os << '(' << fwd_.get() << "," << answer_ << ')';
        }

        Method method_;
        CbcPointer<FwdState> fwd_;
        HappyConnOpener::Answer answer_;
    };

    typedef CbcPointer<HappyConnOpener> Pointer;

    struct PendingConnection {
        Comm::ConnectionPointer path;
        AsyncCall::Pointer connector;

        explicit operator bool() const { return static_cast<bool>(path); }
    };

public:
    HappyConnOpener(const ResolvedPeersPointer &, const AsyncCall::Pointer &,  HttpRequestPointer &, const time_t aFwdStart);
    virtual ~HappyConnOpener() override;

    /// configures reuse of old connections
    void allowPersistent(bool permitted) { allowPconn_ = permitted; }

    /// configures whether the request may be retried later if things go wrong
    void setRetriable(bool retriable) { retriable_ = retriable; }

    /// configures the origin server domain name
    void setHost(const char *);

    /// reacts to changes in the destinations list
    void noteCandidatesChange();

    /// reacts to expired happy_eyeballs_connect_timeout
    void noteGavePrimeItsChance();

    /// reacts to satisfying happy_eyeballs_connect_gap and happy_eyeballs_connect_limit
    void noteSpareAllowance();

    /// the start of the first connection attempt for the currentPeer
    HappyAbsoluteTime primeStart;

private:
    /* AsyncJob API */
    virtual void start() override;
    virtual bool doneAll() const override;
    virtual void swanSong() override;

    void maybeOpenAnotherPrimeConnection();

    void maybeGivePrimeItsChance();
    void stopGivingPrimeItsChance();
    void stopWaitingForSpareAllowance();
    bool maybeOpenSpareConnection();

    // TODO: Describe non-public methods when you define them.

    void startConnecting(PendingConnection &, Comm::ConnectionPointer &);
    void openFreshConnection(PendingConnection &, Comm::ConnectionPointer &);
    bool reuseOldConnection(const Comm::ConnectionPointer &);

    /// Callback called by Comm::ConnOpener objects after a prime or spare
    /// connection attempt completes.
    void connectDone(const CommConnectCbParams &);

    /// Check and start a spare connection if preconditions are satisfied,
    /// or schedules a connection attempt for later.
    void checkForNewConnection();

    void updateSpareWaitAfterPrimeFailure();

    /// Calls the FwdState object back
    void callCallback(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno, bool reused, const char *msg);

    void cancelSpareWait(const char *reason);

    const time_t fwdStart; ///< requestor start time

    AsyncCall::Pointer callback_; ///< handler to be called on connection completion.

    /// Candidate paths. Shared with the initiator (i.e. FwdState object).
    ResolvedPeersPointer destinations;

    /// current connection opening attempt on the prime track (if any)
    PendingConnection prime;

    /// current connection opening attempt on the spare track (if any)
    PendingConnection spare;

    /// CachePeer and IP address family of the peer we are trying to connect
    /// to now (or, if we are just waiting for paths to a new peer, nil)
    Comm::ConnectionPointer currentPeer;

    /// preconditions for an attempt to open a spare connection
    HappySpareWait spareWaiting;
    friend class HappyOrderEnforcer;

    /// whether spare connection attempts disregard happy_eyeballs_* settings
    bool ignoreSpareRestrictions;

    /// whether we have received a permission to open a spare while spares are limited
    bool gotSpareAllowance;

    /// whether persistent connections are allowed
    bool allowPconn_;

    /// whether we are opening connections for a request that may be resent
    bool retriable_;

    const char *host_; ///< origin server domain name

    HttpRequestPointer cause; ///< the request triggered the connection openning

    /// number of connection opening attempts, including those in the requestor
    int n_tries;
};

std::ostream &operator <<(std::ostream &os, const HappyConnOpenerAnswer &answer);

#endif
