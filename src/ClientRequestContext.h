#ifndef SQUID_CLIENTREQUESTCONTEXT_H
#define SQUID_CLIENTREQUESTCONTEXT_H

class ACLChecklist;
class ClientHttpRequest;

#include "config.h"
/* for RefCountable */
#include "RefCount.h"
/* for CBDATA_CLASS() */
#include "cbdata.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#endif

class ClientRequestContext : public RefCountable
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    ClientRequestContext(ClientHttpRequest *);
    ~ClientRequestContext();

    bool httpStateIsValid();
    void clientAccessCheck();
    void clientAccessCheck2();
    void clientAccessCheckDone(int answer);
    void clientRedirectStart();
    void clientRedirectDone(char *result);
    void checkNoCache();
    void checkNoCacheDone(int answer);
#if USE_ADAPTATION

    void adaptationAccessCheck();
    void adaptationAclCheckDone(Adaptation::ServiceGroupPointer g);
#endif
#if USE_SSL
    /**
     * Initiates and start the acl checklist to check if the a CONNECT
     * request must be bumped.
     \retval true if the acl check scheduled, false if no ssl-bump required
     */
    bool sslBumpAccessCheck();
    /// The callback function for ssl-bump access check list
    void sslBumpAccessCheckDone(bool doSslBump);
#endif

    ClientHttpRequest *http;
    ACLChecklist *acl_checklist;        /* need ptr back so we can unreg if needed */
    int redirect_state;

    bool http_access_done;
    bool adapted_http_access_done;
#if USE_ADAPTATION
    bool adaptation_acl_check_done;
#endif
    bool redirect_done;
    bool no_cache_done;
    bool interpreted_req_hdrs;
    bool clientside_tos_done;
#if USE_SSL
    bool sslBumpCheckDone;
#endif

private:
    CBDATA_CLASS(ClientRequestContext);
};

#endif /* SQUID_CLIENTREQUESTCONTEXT_H */
