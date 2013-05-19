#ifndef SQUID_FORWARD_H
#define SQUID_FORWARD_H

#include "Array.h"
#include "comm.h"
#include "comm/Connection.h"
#include "err_type.h"
#include "fde.h"
#include "HttpStatusCode.h"
#include "ip/Address.h"
#include "RefCount.h"

/* forward decls */

class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class ErrorState;
class HttpRequest;

/**
 * Returns the TOS value that we should be setting on the connection
 * to the server, based on the ACL.
 */
tos_t GetTosToServer(HttpRequest * request);

/**
 * Returns the Netfilter mark value that we should be setting on the
 * connection to the server, based on the ACL.
 */
nfmark_t GetNfmarkToServer(HttpRequest * request);

class FwdState : public RefCountable
{
public:
    typedef RefCount<FwdState> Pointer;
    ~FwdState();
    static void initModule();

    /// Initiates request forwarding to a peer or origin server.
    static void Start(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    /// Same as Start() but no master xaction info (AccessLogEntry) available.
    static void fwdStart(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *);

    /// This is the real beginning of server connection. Call it whenever
    /// the forwarding server destination has changed and a new one needs to be opened.
    /// Produces the cannot-forward error on fail if no better error exists.
    void startConnectionOrFail();

    void fail(ErrorState *err);
    void unregister(Comm::ConnectionPointer &conn);
    void unregister(int fd);
    void complete();
    void handleUnregisteredServerEnd();
    int reforward();
    bool reforwardableStatus(http_status s);
    void serverClosed(int fd);
    void connectStart();
    void connectDone(const Comm::ConnectionPointer & conn, comm_err_t status, int xerrno);
    void connectTimeout(int fd);
    void initiateSSL();
    void negotiateSSL(int fd);
    bool checkRetry();
    bool checkRetriable();
    void dispatch();
    void pconnPush(Comm::ConnectionPointer & conn, const char *domain);

    bool dontRetry() { return flags.dont_retry; }

    void dontRetry(bool val) { flags.dont_retry = val; }

    /** return a ConnectionPointer to the current server connection (may or may not be open) */
    Comm::ConnectionPointer const & serverConnection() const { return serverConn; };

private:
    // hidden for safer management of self; use static fwdStart
    FwdState(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    void start(Pointer aSelf);

#if STRICT_ORIGINAL_DST
    void selectPeerForIntercepted();
#endif
    static void logReplyStatus(int tries, http_status status);
    void doneWithRetries();
    void completed();
    void retryOrBail();
    ErrorState *makeConnectingError(const err_type type) const;
    static void RegisterWithCacheManager(void);

public:
    StoreEntry *entry;
    HttpRequest *request;
    AccessLogEntryPointer al; ///< info for the future access.log entry

    static void abort(void*);

private:
    Pointer self;
    ErrorState *err;
    Comm::ConnectionPointer clientConn;        ///< a possibly open connection to the client.
    time_t start_t;
    int n_tries;

    // AsyncCalls which we set and may need cancelling.
    struct {
        AsyncCall::Pointer connector;  ///< a call linking us to the ConnOpener producing serverConn.
    } calls;

    struct {
        unsigned int connected_okay:1; ///< TCP link ever opened properly. This affects retry of POST,PUT,CONNECT,etc
        unsigned int dont_retry:1;
        unsigned int forward_completed:1;
    } flags;

    /** connections to open, in order, until successful */
    Comm::ConnectionList serverDestinations;

    Comm::ConnectionPointer serverConn; ///< a successfully opened connection to a server.

    /// possible pconn race states
    typedef enum { raceImpossible, racePossible, raceHappened } PconnRace;
    PconnRace pconnRace; ///< current pconn race state

    // NP: keep this last. It plays with private/public
    CBDATA_CLASS2(FwdState);
};

void getOutgoingAddress(HttpRequest * request, Comm::ConnectionPointer conn);

#endif /* SQUID_FORWARD_H */
