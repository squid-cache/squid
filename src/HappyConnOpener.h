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

class FwdState;
class CandidatePaths;
typedef RefCount<CandidatePaths> CandidatePathsPointer;

/// Implements Happy Eyeballs (RFC 6555)
/// Each HappyConnOpener object shares a CandidatePaths object with the caller,
/// and informed for changes using the  HappyConnOpener::noteCandidatePath()
/// asyncCall.
/// The CandidatePaths::destinationsFinalized flag is set by caller to inform
/// HappyConnOpener object that the CandidatePaths will not receive any new
/// path.
/// The HappyConnOpener object needs to update the CandidatePaths::readStatus
/// with the current_dtime when access the CandidatePaths object
class HappyConnOpener: public AsyncJob
{
    CBDATA_CLASS(HappyConnOpener);
public:
    /// Informations about connection status to be sent to the caller
    class Answer
    {
    public:
        Comm::ConnectionPointer conn; ///< The last tried connection
        Comm::Flag ioStatus = Comm::OK; ///< The last tried connection status
        const char *host = nullptr; ///< The connected host. Used by pinned connections
        int xerrno = 0; ///< The system error
        const char *status = nullptr; ///< A status message for debugging reasons
        bool reused = false; ///< True if this is a reused connection
        int n_tries = 0; ///< The number of connection tries

        friend std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer);
    };

    /// A dialer object to callback FwdState object
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
    };

public:
    /// Pops a connection from connection pool if available. If not
    /// checks the peer stand-by connection pool for available connection.
    static Comm::ConnectionPointer PconnPop(const Comm::ConnectionPointer &dest, const char *domain, bool retriable);
    /// Push the connection back to connection pool
    static void PconnPush(Comm::ConnectionPointer &conn, const char *domain);
    /// Inform HappyConnOpener subsystem that the connection is closed
    static void ConnectionClosed(const Comm::ConnectionPointer &conn);

    HappyConnOpener(const CandidatePathsPointer &, const AsyncCall::Pointer &, const time_t fwdStart, int tries);
    ~HappyConnOpener();

     /// Inform us that new candidate destinations are available
    void noteCandidatePath();

    /// Whether to use persistent connections
    void allowPersistent(bool p) { allowPconn_ = p; }

    /// Whether the opened connection can be used for a retriable request
    void setRetriable(bool retriable) { retriable_ = retriable; }

    /// Sets the destination hostname
    void setHost(const char *host);

    /// The time period after which the next spare connection can be started
    /// It takes in account the happy_eyeballs_connect_gap and the
    /// happy_eyeballs_connect_timeout.
    double spareMayStartAfter() const;

    /// Start openning a master connection.
    /// Returns true on success false if candidate paths are not available.
    bool startMasterConnection();

    /// Start openning a spare connection.
    /// Returns true on success false if candidate paths are not available.
    bool startSpareConnection();

    void stopWaiting() {waitingSpareConnection_ = false;}

    tos_t useTos; ///< The tos to use for opened connection
    nfmark_t useNfmark;///< the nfmark to use for opened connection

    /// Flag which is set to true if the last try to start a spare
    /// connection failed because candidate paths are not available.
    /// This flag is cleared (set to false), before a new spare
    /// connection try is scheduled.
    bool rang;

    /// The number of spare connections accross all connectors
    static int SpareConnects;
private:
    // AsyncJob API
    virtual void start() override;
    virtual bool doneAll() const override;
    virtual void swanSong() override;

    /// Called after HappyConnector asyncJob started to start a connection
    void startConnecting(PendingConnection &pconn, Comm::ConnectionPointer &);

    /// Callback called by Comm::ConnOpener objects after a master or spare
    /// connection attempt completes.
    void connectDone(const CommConnectCbParams &);

    /// Return the first available candidate path from CandidatePaths  object.
    /// If the given excludeFamily is not 0 ignore CandidatePaths with
    /// this protocol family.
    /// The returned candidate path removed from CandidatePaths object.
    Comm::ConnectionPointer getCandidatePath(int excludeFamily);

    /// \return true if there any candidate path, to try a master or spare
    /// connection.
    bool existCandidatePath();

    /// Check and start a spare connection if preconditions are satisfied,
    /// or schedules a connection attempt for later.
    void checkForNewConnection();

    bool spareConnectionsAllowed() const {return (ConnectLimit() != 0);}

    ///< \return true if the happy_eyeballs_connect_timeout precondition
    /// satisfied
    bool primaryConnectTooSlow() const;

    /// Calls the FwdState object back
    void callCallback(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno, bool reused, const char *msg);

    /// The configured connect_gap per worker basis
    static int ConnectGap();

    /// The configured connect_limit per worker basis
    static int ConnectLimit();

    /// True if the system preconditions for starting a new spare connection
    /// are satisfied. It checks the happy_eyeballs_connect_limit and
    /// happy_eyeballs_connect_gap configuration parameters.
    static bool SpareConnectionAllowedNow();

    AsyncCall::Pointer callback_; ///< handler to be called on connection completion.

    /// The list with candidate destinations. Shared with the caller FwdState object.
    CandidatePathsPointer dests_;

    PendingConnection master; ///< Master pending connection
    PendingConnection spare;  ///< Spare pending connection

    bool allowPconn_; ///< Whether to allow persistent connections
    bool retriable_; ///< Whether to open connection for retriable request

    /// Whether this object is waiting for a new spare connection attempt
    bool waitingSpareConnection_;
    const char *host_; ///< The destination hostname
    time_t fwdStart_; ///< When the forwarding of the related request started
    int maxTries; ///< The connector should not exceed the maxTries tries.
    int n_tries; ///< The number of connection tries.

    /// When the next spare connection attempt can be started
    double nextAttemptTime;

    static double LastAttempt; ///< The time of last spare connection attempt
};

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer);

#endif
