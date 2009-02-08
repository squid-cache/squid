#ifndef SQUID_FORWARD_H
#define SQUID_FORWARD_H

/* forward decls */

class CacheManager;
class ErrorState;
class HttpRequest;

#include "comm.h"

class FwdServer
{

public:
    peer *_peer;                /* NULL --> origin server */
    hier_code code;
    FwdServer *next;
};

class FwdState : public RefCountable
{

public:
    typedef RefCount<FwdState> Pointer;
    ~FwdState();
    static void initModule();
    static void RegisterWithCacheManager(CacheManager & manager);

    static void fwdStart(int fd, StoreEntry *, HttpRequest *);
    void startComplete(FwdServer *);
    void startFail();
    void fail(ErrorState *err);
    void unregister(int fd);
    void complete();
    void handleUnregisteredServerEnd();
    int reforward();
    bool reforwardableStatus(http_status s);
    void serverClosed(int fd);
    void connectStart();
    void connectDone(int server_fd, comm_err_t status, int xerrno);
    void connectTimeout(int fd);
    void initiateSSL();
    void negotiateSSL(int fd);
    bool checkRetry();
    bool checkRetriable();
    void dispatch();
    void pconnPush(int fd, const peer *_peer, const HttpRequest *req, const char *domain, struct in_addr *client_addr);

    bool dontRetry() { return flags.dont_retry; }

    void dontRetry(bool val) { flags.dont_retry = val; }

    bool ftpPasvFailed() { return flags.ftp_pasv_failed; }

    void ftpPasvFailed(bool val) { flags.ftp_pasv_failed = val; }

    static void serversFree(FwdServer **);

private:
    // hidden for safer management of self; use static fwdStart
    FwdState(int fd, StoreEntry *, HttpRequest *);
    void start(Pointer aSelf);

    static void logReplyStatus(int tries, http_status status);
    void updateHierarchyInfo();
    void completed();
    void retryOrBail();

#if WIP_FWD_LOG

    void uninit
    static void logRotate
    void status()
#endif

public:
    StoreEntry *entry;
    HttpRequest *request;
    int server_fd;
    FwdServer *servers;
    static void abort(void*);

private:
    CBDATA_CLASS2(FwdState);
    Pointer self;
    ErrorState *err;
    int client_fd;
    time_t start_t;
    int n_tries;
    int origin_tries;
#if WIP_FWD_LOG

    http_status last_status;
#endif

    struct
    {

unsigned int dont_retry:
        1;

unsigned int ftp_pasv_failed:
        1;

unsigned int forward_completed:1;
    }

    flags;
#if LINUX_NETFILTER
    struct sockaddr_in src;
#endif

};

#endif
