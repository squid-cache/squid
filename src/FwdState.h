/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FORWARD_H
#define SQUID_FORWARD_H

#include "base/forward.h"
#include "base/JobWait.h"
#include "base/RefCount.h"
#include "clients/forward.h"
#include "comm.h"
#include "comm/Connection.h"
#include "error/forward.h"
#include "fde.h"
#include "http/StatusCode.h"
#include "ip/Address.h"
#include "PeerSelectState.h"
#include "ResolvedPeers.h"
#include "security/forward.h"
#if USE_OPENSSL
#include "ssl/support.h"
#endif

/* forward decls */

class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class ErrorState;
class HttpRequest;
class PconnPool;
class ResolvedPeers;
typedef RefCount<ResolvedPeers> ResolvedPeersPointer;

class HappyConnOpener;
class HappyConnOpenerAnswer;

/// Sets initial TOS value and Netfilter for the future outgoing connection.
/// Updates the given Connection object, not the future transport connection.
void GetMarkingsToServer(HttpRequest * request, Comm::Connection &conn);

/// Recomputes and applies TOS value and Netfilter to the outgoing connection.
/// Updates both the given Connection object and the transport connection.
void ResetMarkingsToServer(HttpRequest *, Comm::Connection &);

class HelperReply;

class FwdState: public RefCountable, public PeerSelectionInitiator
{
    CBDATA_CHILD(FwdState);

public:
    typedef RefCount<FwdState> Pointer;
    virtual ~FwdState();
    static void initModule();

    /// Initiates request forwarding to a peer or origin server.
    static void Start(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    /// Same as Start() but no master xaction info (AccessLogEntry) available.
    static void fwdStart(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *);
    /// time left to finish the whole forwarding process (which started at fwdStart)
    static time_t ForwardTimeout(const time_t fwdStart);
    /// Whether there is still time to re-try after a previous connection failure.
    /// \param fwdStart The start time of the peer selection/connection process.
    static bool EnoughTimeToReForward(const time_t fwdStart);

    /// This is the real beginning of server connection. Call it whenever
    /// the forwarding server destination has changed and a new one needs to be opened.
    /// Produces the cannot-forward error on fail if no better error exists.
    void useDestinations();

    void fail(ErrorState *err);
    void unregister(Comm::ConnectionPointer &conn);
    void unregister(int fd);
    void complete();

    /// Mark reply as written to Store in its entirety, including the header and
    /// any body. If the reply has a body, the entire body has to be stored.
    void markStoredReplyAsWhole(const char *whyWeAreSure);

    void handleUnregisteredServerEnd();
    int reforward();
    bool reforwardableStatus(const Http::StatusCode s) const;
    void serverClosed();
    void connectStart();
    void connectDone(const Comm::ConnectionPointer & conn, Comm::Flag status, int xerrno);
    bool checkRetry();
    bool checkRetriable();
    void dispatch();

    void pconnPush(Comm::ConnectionPointer & conn, const char *domain);

    bool dontRetry() { return flags.dont_retry; }

    void dontRetry(bool val) { flags.dont_retry = val; }

    /// get rid of a to-server connection that failed to become serverConn
    void closePendingConnection(const Comm::ConnectionPointer &conn, const char *reason);

    /** return a ConnectionPointer to the current server connection (may or may not be open) */
    Comm::ConnectionPointer const & serverConnection() const { return serverConn; };

private:
    // hidden for safer management of self; use static fwdStart
    FwdState(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    void start(Pointer aSelf);
    void stopAndDestroy(const char *reason);

    /* PeerSelectionInitiator API */
    virtual void noteDestination(Comm::ConnectionPointer conn) override;
    virtual void noteDestinationsEnd(ErrorState *selectionError) override;

    bool transporting() const;

    void noteConnection(HappyConnOpenerAnswer &);

#if STRICT_ORIGINAL_DST
    void selectPeerForIntercepted();
#endif
    static void logReplyStatus(int tries, const Http::StatusCode status);
    void doneWithRetries();
    void completed();
    void retryOrBail();

    void usePinned();

    /// whether a pinned to-peer connection can be replaced with another one
    /// (in order to retry or reforward a failed request)
    bool pinnedCanRetry() const;

    template <typename StepStart>
    void advanceDestination(const char *stepDescription, const Comm::ConnectionPointer &conn, const StepStart &startStep);

    ErrorState *makeConnectingError(const err_type type) const;
    void connectedToPeer(Security::EncryptorAnswer &answer);
    static void RegisterWithCacheManager(void);

    void establishTunnelThruProxy(const Comm::ConnectionPointer &);
    void tunnelEstablishmentDone(Http::TunnelerAnswer &answer);
    void secureConnectionToPeerIfNeeded(const Comm::ConnectionPointer &);
    void secureConnectionToPeer(const Comm::ConnectionPointer &);
    void successfullyConnectedToPeer(const Comm::ConnectionPointer &);

    /// stops monitoring server connection for closure and updates pconn stats
    void closeServerConnection(const char *reason);

    void syncWithServerConn(const Comm::ConnectionPointer &server, const char *host, const bool reused);
    void syncHierNote(const Comm::ConnectionPointer &server, const char *host);

    /// whether we have used up all permitted forwarding attempts
    bool exhaustedTries() const;

    /// \returns the time left for this connection to become connected or 1 second if it is less than one second left
    time_t connectingTimeout(const Comm::ConnectionPointer &conn) const;

    void cancelStep(const char *reason);

    void notifyConnOpener();
    void reactToZeroSizeObject();

    void updateAleWithFinalError();

public:
    StoreEntry *entry;
    HttpRequest *request;
    AccessLogEntryPointer al; ///< info for the future access.log entry

    /// called by Store if the entry is no longer usable
    static void HandleStoreAbort(FwdState *);

private:
    Pointer self;
    ErrorState *err;
    Comm::ConnectionPointer clientConn;        ///< a possibly open connection to the client.
    time_t start_t;
    int n_tries; ///< the number of forwarding attempts so far

    struct {
        bool connected_okay; ///< TCP link ever opened properly. This affects retry of POST,PUT,CONNECT,etc
        bool dont_retry;
        bool forward_completed;
        bool destinationsFound; ///< at least one candidate path found
    } flags;

    /// waits for a transport connection to the peer to be established/opened
    JobWait<HappyConnOpener> transportWait;

    /// waits for the established transport connection to be secured/encrypted
    JobWait<Security::PeerConnector> encryptionWait;

    /// waits for an HTTP CONNECT tunnel through a cache_peer to be negotiated
    /// over the (encrypted, if needed) transport connection to that cache_peer
    JobWait<Http::Tunneler> peerWait;

    /// whether we are waiting for the last dispatch()ed activity to end
    bool waitingForDispatched;

    ResolvedPeersPointer destinations; ///< paths for forwarding the request
    Comm::ConnectionPointer serverConn; ///< a successfully opened connection to a server.
    PeerConnectionPointer destinationReceipt; ///< peer selection result (or nil)

    AsyncCall::Pointer closeHandler; ///< The serverConn close handler

    /// possible pconn race states
    typedef enum { raceImpossible, racePossible, raceHappened } PconnRace;
    PconnRace pconnRace; ///< current pconn race state

    /// Whether the entire reply (including any body) was written to Store.
    /// The string literal value is only used for debugging.
    const char *storedWholeReply_;
};

void getOutgoingAddress(HttpRequest * request, const Comm::ConnectionPointer &conn);

/// a collection of previously used persistent Squid-to-peer HTTP(S) connections
extern PconnPool *fwdPconnPool;

#endif /* SQUID_FORWARD_H */

