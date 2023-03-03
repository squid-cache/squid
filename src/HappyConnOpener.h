/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
#include "log/forward.h"
#include "ResolvedPeers.h"

#include <iosfwd>

class HappyConnOpener;
class HappyOrderEnforcer;
class JobGapEnforcer;
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

    CodeContext::Pointer codeContext; ///< requestor's context

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
    ~HappyConnOpenerAnswer();

    /// whether HappyConnOpener succeeded, returning a usable connection
    bool success() const { return !error; }

    /// on success: an open, ready-to-use Squid-to-peer connection
    /// on failure: either a closed failed Squid-to-peer connection or nil
    PeerConnectionPointer conn;

    // answer recipients must clear the error member in order to keep its info
    // XXX: We should refcount ErrorState instead of cbdata-protecting it.
    CbcPointer<ErrorState> error; ///< problem details (nil on success)

    /// The total number of attempts to establish a connection. Includes any
    /// failed attempts and [always successful] persistent connection reuse.
    int n_tries = 0;

    /// whether conn was open earlier, by/for somebody else
    bool reused = false;
};

/// reports Answer details (for AsyncCall parameter debugging)
std::ostream &operator <<(std::ostream &, const HappyConnOpenerAnswer &);

/// A TCP connection opening algorithm based on Happy Eyeballs (RFC 8305).
/// Maintains two concurrent connection opening tracks: prime and spare.
/// Shares ResolvedPeers list with the job initiator.
class HappyConnOpener: public AsyncJob
{
    CBDATA_CHILD(HappyConnOpener);
public:
    typedef HappyConnOpenerAnswer Answer;

public:
    HappyConnOpener(const ResolvedPeersPointer &, const AsyncCallback<Answer> &, const HttpRequestPointer &, time_t aFwdStart, int tries, const AccessLogEntryPointer &);
    ~HappyConnOpener() override;

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
    HappyAbsoluteTime primeStart = 0;

private:
    /// a connection opening attempt in progress (or falsy)
    class Attempt {
    public:
        /// HappyConnOpener method implementing a ConnOpener callback
        using CallbackMethod = void (HappyConnOpener::*)(const CommConnectCbParams &);

        Attempt(const CallbackMethod method, const char *methodName);

        explicit operator bool() const { return static_cast<bool>(path); }

        /// reacts to a natural attempt completion (successful or otherwise)
        void finish();

        /// aborts an in-progress attempt
        void cancel(const char *reason);

        PeerConnectionPointer path; ///< the destination we are connecting to

        /// waits for a connection to the peer to be established/opened
        JobWait<Comm::ConnOpener> connWait;

        const CallbackMethod callbackMethod; ///< ConnOpener calls this method
        const char * const callbackMethodName; ///< for callbackMethod debugging
    };
    friend std::ostream &operator <<(std::ostream &, const Attempt &);

    /* AsyncJob API */
    void start() override;
    bool doneAll() const override;
    void swanSong() override;
    const char *status() const override;

    void maybeOpenPrimeConnection();
    void maybeOpenSpareConnection();

    void maybeGivePrimeItsChance();
    void stopGivingPrimeItsChance();
    void stopWaitingForSpareAllowance();

    void startConnecting(Attempt &, PeerConnectionPointer &);
    void openFreshConnection(Attempt &, PeerConnectionPointer &);
    bool reuseOldConnection(PeerConnectionPointer &);

    void notePrimeConnectDone(const CommConnectCbParams &);
    void noteSpareConnectDone(const CommConnectCbParams &);
    void handleConnOpenerAnswer(Attempt &, const CommConnectCbParams &, const char *connDescription);

    void checkForNewConnection();

    void updateSpareWaitAfterPrimeFailure();

    void cancelSpareWait(const char *reason);

    bool ranOutOfTimeOrAttempts() const;

    ErrorState *makeError(const err_type type) const;
    Answer *futureAnswer(const PeerConnectionPointer &);
    void sendSuccess(const PeerConnectionPointer &conn, bool reused, const char *connKind);
    void sendFailure();
    void cancelAttempt(Attempt &, const char *reason);

    const time_t fwdStart; ///< requestor start time

    /// answer destination
    AsyncCallback<Answer> callback_;

    /// Candidate paths. Shared with the initiator. May not be finalized yet.
    ResolvedPeersPointer destinations;

    /// current connection opening attempt on the prime track (if any)
    Attempt prime;

    /// current connection opening attempt on the spare track (if any)
    Attempt spare;

    /// CachePeer and IP address family of the peer we are trying to connect
    /// to now (or, if we are just waiting for paths to a new peer, nil)
    Comm::ConnectionPointer currentPeer;

    /// preconditions for an attempt to open a spare connection
    HappySpareWait spareWaiting;
    friend class HappyOrderEnforcer;

    AccessLogEntryPointer ale; ///< transaction details

    ErrorState *lastError = nullptr; ///< last problem details (or nil)
    PeerConnectionPointer lastFailedConnection; ///< nil if none has failed

    /// whether spare connection attempts disregard happy_eyeballs_* settings
    bool ignoreSpareRestrictions = false;

    /// whether we have received a permission to open a spare while spares are limited
    bool gotSpareAllowance = false;

    /// whether persistent connections are allowed
    bool allowPconn_ = true;

    /// whether we are opening connections for a request that may be resent
    bool retriable_ = true;

    /// origin server domain name (or equivalent)
    const char *host_ = nullptr;

    /// the request that needs a to-server connection
    HttpRequestPointer cause;

    /// number of our finished connection opening attempts (including pconn
    /// reuses) plus previously finished attempts supplied by the requestor
    int n_tries;

    /// Reason to ran out of time or attempts
    mutable const char *ranOutOfTimeOrAttemptsEarlier_ = nullptr;
};

#endif

