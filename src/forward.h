#ifndef SQUID_FORWARD_H
#define SQUID_FORWARD_H

/* forward decls */

class ErrorState;
class HttpRequest;

#include "comm.h"
#include "comm/Connection.h"
#include "ip/Address.h"
#include "Array.h"

class FwdState : public RefCountable
{
public:
    typedef RefCount<FwdState> Pointer;
    ~FwdState();
    static void initModule();

    static void fwdStart(int fd, StoreEntry *, HttpRequest *);
    void startComplete();
    void fail(ErrorState *err);
    void unregister(int fd);
    void complete();
    void handleUnregisteredServerEnd();
    int reforward();
    bool reforwardableStatus(http_status s);
    void serverClosed(int fd);
    void connectStart();
    void connectDone(Comm::Connection::Pointer conn, Vector<Comm::Connection::Pointer> *paths, comm_err_t status, int xerrno);
    void connectTimeout(int fd);
    void initiateSSL();
    void negotiateSSL(int fd);
    bool checkRetry();
    bool checkRetriable();
    void dispatch();
    void pconnPush(Comm::Connection::Pointer conn, const peer *_peer, const HttpRequest *req, const char *domain, Ip::Address &client_addr);

    bool dontRetry() { return flags.dont_retry; }

    void dontRetry(bool val) { flags.dont_retry = val; }

    bool ftpPasvFailed() { return flags.ftp_pasv_failed; }

    void ftpPasvFailed(bool val) { flags.ftp_pasv_failed = val; }

    Comm::Connection::Pointer conn() const { return paths[0]; };

private:
    // hidden for safer management of self; use static fwdStart
    FwdState(int fd, StoreEntry *, HttpRequest *);
    void start(Pointer aSelf);

    static void logReplyStatus(int tries, http_status status);
    void updateHierarchyInfo();
    void completed();
    void retryOrBail();
    static void RegisterWithCacheManager(void);

#if WIP_FWD_LOG

    void uninit                /**DOCS_NOSEMI*/
    static void logRotate      /**DOCS_NOSEMI*/
    void status()              /**DOCS_NOSEMI*/
#endif

public:
    StoreEntry *entry;
    HttpRequest *request;
    static void abort(void*);

private:
    Pointer self;
    ErrorState *err;
    int client_fd;
    time_t start_t;
    int n_tries;
    int origin_tries;
#if WIP_FWD_LOG

    http_status last_status;
#endif

    struct {
        unsigned int dont_retry:1;
        unsigned int ftp_pasv_failed:1;
        unsigned int forward_completed:1;
    } flags;

    /** possible paths which may be tried (in sequence stored) */
    Vector<Comm::Connection::Pointer> paths;

    // NP: keep this last. It plays with private/public
    CBDATA_CLASS2(FwdState);
};

#endif /* SQUID_FORWARD_H */
