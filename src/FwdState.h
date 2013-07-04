#ifndef SQUID_FORWARD_H
#define SQUID_FORWARD_H

#include "base/Vector.h"
#include "base/RefCount.h"
#include "comm.h"
#include "comm/Connection.h"
#include "err_type.h"
#include "fde.h"
#include "http/StatusCode.h"
#include "ip/Address.h"
#if USE_SSL
#include "ssl/support.h"
#endif

/* forward decls */

class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class ErrorState;
class HttpRequest;

#if USE_SSL
namespace Ssl
{
class ErrorDetail;
class CertValidationResponse;
};
#endif

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

class HelperReply;

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
    bool reforwardableStatus(const Http::StatusCode s) const;
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

#if USE_SSL
    /// Callback function called when squid receive message from cert validator helper
    static void sslCrtvdHandleReplyWrapper(void *data, Ssl::CertValidationResponse const &);
    /// Process response from cert validator helper
    void sslCrtvdHandleReply(Ssl::CertValidationResponse const &);
    /// Check SSL errors returned from cert validator against sslproxy_cert_error access list
    Ssl::CertErrors *sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &, Ssl::ErrorDetail *&);
#endif
private:
    // hidden for safer management of self; use static fwdStart
    FwdState(const Comm::ConnectionPointer &client, StoreEntry *, HttpRequest *, const AccessLogEntryPointer &alp);
    void start(Pointer aSelf);

#if STRICT_ORIGINAL_DST
    void selectPeerForIntercepted();
#endif
    static void logReplyStatus(int tries, const Http::StatusCode status);
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
        bool connected_okay; ///< TCP link ever opened properly. This affects retry of POST,PUT,CONNECT,etc
        bool dont_retry;
        bool forward_completed;
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
