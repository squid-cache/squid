#include "squid.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "client_side.h"
#include "auth/UserRequest.h"
#include "auth/AclProxyAuth.h"
#include "acl/FilledChecklist.h"

CBDATA_CLASS_INIT(ACLFilledChecklist);

#if MOVED
int
ACLFilledChecklist::authenticated()
{
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
    AuthUserRequest *old_auth_user_request = auth_user_request;
    auth_acl_t result = AuthUserRequest::tryToAuthenticateAndSetAuthUser (&auth_user_request, headertype, request, conn(), src_addr);
    if (auth_user_request)
        AUTHUSERREQUESTLOCK(auth_user_request, "ACLFilledChecklist");
    AUTHUSERREQUESTUNLOCK(old_auth_user_request, "old ACLFilledChecklist");
    switch (result) {

    case AUTH_ACL_CANNOT_AUTHENTICATE:
        debugs(28, 4, "aclMatchAcl: returning  0 user authenticated but not authorised.");
        return 0;

    case AUTH_AUTHENTICATED:

        return 1;
        break;

    case AUTH_ACL_HELPER:
        debugs(28, 4, "aclMatchAcl: returning 0 sending credentials to helper.");
        changeState (ProxyAuthLookup::Instance());
        return 0;

    case AUTH_ACL_CHALLENGE:
        debugs(28, 4, "aclMatchAcl: returning 0 sending authentication challenge.");
        changeState (ProxyAuthNeeded::Instance());
        return 0;

    default:
        fatal("unexpected authenticateAuthenticate reply\n");
        return 0;
    }
}
#endif

void
ACLFilledChecklist::checkCallback(allow_t answer)
{
    debugs(28, 5, "ACLFilledChecklist::checkCallback: " << this << " answer=" << answer);

    /* During reconfigure, we can end up not finishing call
     * sequences into the auth code */

    if (auth_user_request) {
        /* the filled_checklist lock */
        AUTHUSERREQUESTUNLOCK(auth_user_request, "ACLFilledChecklist");
        /* it might have been connection based */
        assert(conn() != NULL);
        /*
         * DPW 2007-05-08
         * yuck, this make me uncomfortable.  why do this here?
         * ConnStateData will do its own unlocking.
         */
        AUTHUSERREQUESTUNLOCK(conn()->auth_user_request, "conn via ACLFilledChecklist");
        conn()->auth_type = AUTH_BROKEN;
    }

    ACLChecklist::checkCallback(answer); // may delete us
}


void *
ACLFilledChecklist::operator new (size_t size)
{
    assert (size == sizeof(ACLFilledChecklist));
    CBDATA_INIT_TYPE(ACLFilledChecklist);
    ACLFilledChecklist *result = cbdataAlloc(ACLFilledChecklist);
    return result;
}

void
ACLFilledChecklist::operator delete (void *address)
{
    ACLFilledChecklist *t = static_cast<ACLFilledChecklist *>(address);
    cbdataFree(t);
}


ACLFilledChecklist::ACLFilledChecklist() :
        dst_peer(NULL),
        dst_rdns(NULL),
        request (NULL),
        reply (NULL),
        auth_user_request (NULL),
#if SQUID_SNMP
        snmp_community(NULL),
#endif
#if USE_SSL
        ssl_error(0),
#endif
        extacl_entry (NULL),
        conn_(NULL),
        fd_(-1),
        destinationDomainChecked_(false),
        sourceDomainChecked_(false)
{
    my_addr.SetEmpty();
    src_addr.SetEmpty();
    dst_addr.SetEmpty();
    rfc931[0] = '\0';
}


ACLFilledChecklist::~ACLFilledChecklist()
{
    assert (!asyncInProgress());

    safe_free(dst_rdns); // created by xstrdup().

    if (extacl_entry)
        cbdataReferenceDone(extacl_entry);

    HTTPMSGUNLOCK(request);

    HTTPMSGUNLOCK(reply);

    // no auth_user_request in builds without any Authentication configured
    if (auth_user_request)
        AUTHUSERREQUESTUNLOCK(auth_user_request, "ACLFilledChecklist destructor");

    cbdataReferenceDone(conn_);

    debugs(28, 4, HERE << "ACLFilledChecklist destroyed " << this);
}


ConnStateData *
ACLFilledChecklist::conn() const
{
    return  conn_;
}

void
ACLFilledChecklist::conn(ConnStateData *aConn)
{
    assert (conn() == NULL);
    conn_ = cbdataReference(aConn);
}

int
ACLFilledChecklist::fd() const
{
    return conn_ != NULL ? conn_->fd : fd_;
}

void
ACLFilledChecklist::fd(int aDescriptor)
{
    assert(!conn() || conn()->fd == aDescriptor);
    fd_ = aDescriptor;
}

bool
ACLFilledChecklist::destinationDomainChecked() const
{
    return destinationDomainChecked_;
}

void
ACLFilledChecklist::markDestinationDomainChecked()
{
    assert (!finished() && !destinationDomainChecked());
    destinationDomainChecked_ = true;
}

bool
ACLFilledChecklist::sourceDomainChecked() const
{
    return sourceDomainChecked_;
}

void
ACLFilledChecklist::markSourceDomainChecked()
{
    assert (!finished() && !sourceDomainChecked());
    sourceDomainChecked_ = true;
}

/*
 * There are two common ACLFilledChecklist lifecycles paths:
 *
 * A) Using aclCheckFast(): The caller creates an ACLFilledChecklist object
 *    on stack and calls aclCheckFast().
 *
 * B) Using aclNBCheck() and callbacks: The caller allocates an
 *    ACLFilledChecklist object (via operator new) and passes it to
 *    aclNBCheck(). Control eventually passes to ACLChecklist::checkCallback(),
 *    which will invoke the callback function as requested by the
 *    original caller of aclNBCheck().  This callback function must
 *    *not* delete the list.  After the callback function returns,
 *    checkCallback() will delete the list (i.e., self).
 */
ACLFilledChecklist::ACLFilledChecklist(const acl_access *A, HttpRequest *http_request, const char *ident):
        dst_peer(NULL),
        dst_rdns(NULL),
        request(NULL),
        reply(NULL),
        auth_user_request(NULL),
#if SQUID_SNMP
        snmp_community(NULL),
#endif
#if USE_SSL
        ssl_error(0),
#endif
        extacl_entry (NULL),
        conn_(NULL),
        fd_(-1),
        destinationDomainChecked_(false),
        sourceDomainChecked_(false)
{
    my_addr.SetEmpty();
    src_addr.SetEmpty();
    dst_addr.SetEmpty();
    rfc931[0] = '\0';

    // cbdataReferenceDone() is in either fastCheck() or the destructor
    if (A)
        accessList = cbdataReference(A);

    if (http_request != NULL) {
        request = HTTPMSGLOCK(http_request);
#if FOLLOW_X_FORWARDED_FOR
        if (Config.onoff.acl_uses_indirect_client)
            src_addr = request->indirect_client_addr;
        else
#endif /* FOLLOW_X_FORWARDED_FOR */
            src_addr = request->client_addr;
        my_addr = request->my_addr;
    }

#if USE_IDENT
    if (ident)
        xstrncpy(rfc931, ident, USER_IDENT_SZ);
#endif
}

