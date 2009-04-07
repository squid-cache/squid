#include "squid.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "auth/UserRequest.h"
#include "auth/Acl.h"
#include "auth/AclProxyAuth.h"
#include "HttpRequest.h"

/** retval -1 user not authenticated (authentication error?)
    retval  0 user not authorized OR user authentication is in pgrogress
    retval +1 user authenticated and authorized */
int
AuthenticateAcl(ACLChecklist *ch)
{
    ACLFilledChecklist *checklist = Filled(ch);
    HttpRequest *request = checklist->request;
    http_hdr_type headertype;

    if (NULL == request) {
        fatal ("requiresRequest SHOULD have been true for this ACL!!");
        return 0;
    } else if (request->flags.accelerated) {
        /* WWW authorization on accelerated requests */
        headertype = HDR_AUTHORIZATION;
    } else if (request->flags.intercepted || request->flags.spoof_client_ip) {
        debugs(28, DBG_IMPORTANT, HERE << " authentication not applicable on intercepted requests.");
        return -1;
    } else {
        /* Proxy authorization on proxy requests */
        headertype = HDR_PROXY_AUTHORIZATION;
    }

    /* get authed here */
    /* Note: this fills in auth_user_request when applicable */
    /*
     * DPW 2007-05-08
     * tryToAuthenticateAndSetAuthUser used to try to lock and
     * unlock auth_user_request on our behalf, but it was too
     * ugly and hard to follow.  Now we do our own locking here.
     *
     * I'm not sure what tryToAuthenticateAndSetAuthUser does when
     * auth_user_request is set before calling.  I'm tempted to
     * unlock and set it to NULL, but it seems safer to save the
     * pointer before calling and unlock it afterwards.  If the
     * pointer doesn't change then its a no-op.
     */
    AuthUserRequest *old_auth_user_request = checklist->auth_user_request;
    const auth_acl_t result = AuthUserRequest::tryToAuthenticateAndSetAuthUser(
                                  &checklist->auth_user_request, headertype, request,
                                  checklist->conn(), checklist->src_addr);
    if (checklist->auth_user_request)
        AUTHUSERREQUESTLOCK(checklist->auth_user_request, "ACLAuth::authenticated");
    AUTHUSERREQUESTUNLOCK(old_auth_user_request, "old ACLAuth");
    switch (result) {

    case AUTH_ACL_CANNOT_AUTHENTICATE:
        debugs(28, 4, HERE << "returning  0 user authenticated but not authorised.");
        return 0;

    case AUTH_AUTHENTICATED:
        return 1;
        break;

    case AUTH_ACL_HELPER:
        debugs(28, 4, HERE << "returning 0 sending credentials to helper.");
        checklist->changeState(ProxyAuthLookup::Instance());
        return 0;

    case AUTH_ACL_CHALLENGE:
        debugs(28, 4, HERE << "returning 0 sending authentication challenge.");
        checklist->changeState (ProxyAuthNeeded::Instance());
        return 0;

    default:
        fatal("unexpected authenticateAuthenticate reply\n");
        return 0;
    }
}
