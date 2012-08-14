#ifndef SQUID_CLIENTREQUESTCONTEXT_H
#define SQUID_CLIENTREQUESTCONTEXT_H

#include "cbdata.h"
#include "RefCount.h"
#include "ipcache.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#endif

class ACLChecklist;
class ClientHttpRequest;
class DnsLookupDetails;
class ErrorState;

class ClientRequestContext : public RefCountable
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    ClientRequestContext(ClientHttpRequest *);
    ~ClientRequestContext();

    bool httpStateIsValid();
    void hostHeaderVerify();
    void hostHeaderIpVerify(const ipcache_addrs* ia, const DnsLookupDetails &dns);
    void hostHeaderVerifyFailed(const char *A, const char *B);
    void clientAccessCheck();
    void clientAccessCheck2();
    void clientAccessCheckDone(const allow_t &answer);
    void clientRedirectStart();
    void clientRedirectDone(char *result);
    void checkNoCache();
    void checkNoCacheDone(const allow_t &answer);
#if USE_ADAPTATION

    void adaptationAccessCheck();
#endif
#if USE_SSL
    /**
     * Initiates and start the acl checklist to check if the a CONNECT
     * request must be bumped.
     \retval true if the acl check scheduled, false if no ssl-bump required
     */
    bool sslBumpAccessCheck();
    /// The callback function for ssl-bump access check list
    void sslBumpAccessCheckDone(const allow_t &answer);
#endif

    ClientHttpRequest *http;
    ACLChecklist *acl_checklist;        /* need ptr back so we can unreg if needed */
    int redirect_state;

    bool host_header_verify_done;
    bool http_access_done;
    bool adapted_http_access_done;
#if USE_ADAPTATION
    bool adaptation_acl_check_done;
#endif
    bool redirect_done;
    bool no_cache_done;
    bool interpreted_req_hdrs;
    bool tosToClientDone;
    bool nfmarkToClientDone;
#if USE_SSL
    bool sslBumpCheckDone;
#endif
    ErrorState *error; ///< saved error page for centralized/delayed processing
    bool readNextRequest; ///< whether Squid should read after error handling

private:
    CBDATA_CLASS(ClientRequestContext);
};

#endif /* SQUID_CLIENTREQUESTCONTEXT_H */
