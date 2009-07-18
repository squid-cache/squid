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
    void clientAccessCheckDone(int answer);
    void clientRedirectStart();
    void clientRedirectDone(char *result);
    void checkNoCache();
    void checkNoCacheDone(int answer);
#if USE_ADAPTATION

    void adaptationAccessCheck();
    void adaptationAclCheckDone(Adaptation::ServiceGroupPointer g);
#endif

    ClientHttpRequest *http;
    ACLChecklist *acl_checklist;        /* need ptr back so we can unreg if needed */
    int redirect_state;

    bool http_access_done;
#if USE_ADAPTATION

    bool adaptation_acl_check_done;
#endif

    bool redirect_done;
    bool no_cache_done;
    bool interpreted_req_hdrs;
    bool clientside_tos_done;

private:
    CBDATA_CLASS(ClientRequestContext);
};

#endif /* SQUID_CLIENTREQUESTCONTEXT_H */
