#include "config.h"
#include "auth/digest/auth_digest.h"
#include "auth/digest/digestUserRequest.h"
#include "auth/State.h"
#include "charset.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidTime.h"

AuthDigestUserRequest::AuthDigestUserRequest() :
        nonceb64(NULL),
        cnonce(NULL),
        realm(NULL),
        pszPass(NULL),
        algorithm(NULL),
        pszMethod(NULL),
        qop(NULL),
        uri(NULL),
        response(NULL),
        nonce(NULL)
{}

/**
 * Delete the digest request structure.
 * Does NOT delete related AuthUser structures
 */
AuthDigestUserRequest::~AuthDigestUserRequest()
{
    assert(RefCountCount()==0);

    safe_free(nonceb64);
    safe_free(cnonce);
    safe_free(realm);
    safe_free(pszPass);
    safe_free(algorithm);
    safe_free(pszMethod);
    safe_free(qop);
    safe_free(uri);
    safe_free(response);

    if (nonce)
        authDigestNonceUnlink(nonce);
}

int
AuthDigestUserRequest::authenticated() const
{
    if (user() != NULL && user()->credentials() == AuthUser::Ok)
        return 1;

    return 0;
}

/** log a digest user in
 */
void
AuthDigestUserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
{
    HASHHEX SESSIONKEY;
    HASHHEX HA2 = "";
    HASHHEX Response;

    /* if the check has corrupted the user, just return */
    if (user() == NULL || user()->credentials() == AuthUser::Failed) {
        return;
    }

    AuthUser::Pointer auth_user = user();

    DigestUser *digest_user = dynamic_cast<DigestUser*>(auth_user.getRaw());
    assert(digest_user != NULL);

    AuthDigestUserRequest *digest_request = this;

    /* do we have the HA1 */
    if (!digest_user->HA1created) {
        auth_user->credentials(AuthUser::Pending);
        return;
    }

    if (digest_request->nonce == NULL) {
        /* this isn't a nonce we issued */
        auth_user->credentials(AuthUser::Failed);
        return;
    }

    DigestCalcHA1(digest_request->algorithm, NULL, NULL, NULL,
                  authenticateDigestNonceNonceb64(digest_request->nonce),
                  digest_request->cnonce,
                  digest_user->HA1, SESSIONKEY);
    DigestCalcResponse(SESSIONKEY, authenticateDigestNonceNonceb64(digest_request->nonce),
                       digest_request->nc, digest_request->cnonce, digest_request->qop,
                       RequestMethodStr(request->method), digest_request->uri, HA2, Response);

    debugs(29, 9, "\nResponse = '" << digest_request->response << "'\nsquid is = '" << Response << "'");

    if (strcasecmp(digest_request->response, Response) != 0) {
        if (!digest_request->flags.helper_queried) {
            /* Query the helper in case the password has changed */
            digest_request->flags.helper_queried = 1;
            auth_user->credentials(AuthUser::Pending);
            return;
        }

        if (static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->PostWorkaround && request->method != METHOD_GET) {
            /* Ugly workaround for certain very broken browsers using the
             * wrong method to calculate the request-digest on POST request.
             * This should be deleted once Digest authentication becomes more
             * widespread and such broken browsers no longer are commonly
             * used.
             */
            DigestCalcResponse(SESSIONKEY, authenticateDigestNonceNonceb64(digest_request->nonce),
                               digest_request->nc, digest_request->cnonce, digest_request->qop,
                               RequestMethodStr(METHOD_GET), digest_request->uri, HA2, Response);

            if (strcasecmp(digest_request->response, Response)) {
                auth_user->credentials(AuthUser::Failed);
                digest_request->flags.invalid_password = 1;
                digest_request->setDenyMessage("Incorrect password");
                return;
            } else {
                const char *useragent = request->header.getStr(HDR_USER_AGENT);

                static Ip::Address last_broken_addr;
                static int seen_broken_client = 0;

                if (!seen_broken_client) {
                    last_broken_addr.SetNoAddr();
                    seen_broken_client = 1;
                }

                if (last_broken_addr != request->client_addr) {
                    debugs(29, 1, "\nDigest POST bug detected from " <<
                           request->client_addr << " using '" <<
                           (useragent ? useragent : "-") <<
                           "'. Please upgrade browser. See Bug #630 for details.");

                    last_broken_addr = request->client_addr;
                }
            }
        } else {
            auth_user->credentials(AuthUser::Failed);
            digest_request->flags.invalid_password = 1;
            digest_request->setDenyMessage("Incorrect password");
            return;
        }

        /* check for stale nonce */
        if (!authDigestNonceIsValid(digest_request->nonce, digest_request->nc)) {
            debugs(29, 3, "authenticateDigestAuthenticateuser: user '" << auth_user->username() << "' validated OK but nonce stale");
            auth_user->credentials(AuthUser::Failed);
            digest_request->setDenyMessage("Stale nonce");
            return;
        }
    }

    auth_user->credentials(AuthUser::Ok);

    /* password was checked and did match */
    debugs(29, 4, "authenticateDigestAuthenticateuser: user '" << auth_user->username() << "' validated OK");

    /* auth_user is now linked, we reset these values
     * after external auth occurs anyway */
    auth_user->expiretime = current_time.tv_sec;
    return;
}

int
AuthDigestUserRequest::module_direction()
{
    if (user()->auth_type != AUTH_DIGEST)
        return -2;

    switch (user()->credentials()) {

    case AuthUser::Ok:
        return 0;

    case AuthUser::Failed:
        /* send new challenge */
        return 1;

    case AuthUser::Unchecked:
    case AuthUser::Pending:
        return -1;

    default:
        return -2;
    }
}

/* add the [proxy]authorisation header */
void
AuthDigestUserRequest::addHeader(HttpReply * rep, int accel)
{
    http_hdr_type type;

    /* don't add to authentication error pages */

    if ((!accel && rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (accel && rep->sline.status == HTTP_UNAUTHORIZED))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

#if WAITING_FOR_TE
    /* test for http/1.1 transfer chunked encoding */
    if (chunkedtest)
        return;
#endif

    if ((static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->authenticate) && authDigestNonceLastRequest(nonce)) {
        flags.authinfo_sent = 1;
        debugs(29, 9, "authDigestAddHead: Sending type:" << type << " header: 'nextnonce=\"" << authenticateDigestNonceNonceb64(nonce) << "\"");
        httpHeaderPutStrf(&rep->header, type, "nextnonce=\"%s\"", authenticateDigestNonceNonceb64(nonce));
    }
}

#if WAITING_FOR_TE
/** add the [proxy]authorisation header */
void
AuthDigestUserRequest::addTrailer(HttpReply * rep, int accel)
{
    int type;

    if (!auth_user_request)
        return;

    /* has the header already been send? */
    if (flags.authinfo_sent)
        return;

    /* don't add to authentication error pages */
    if ((!accel && rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (accel && rep->sline.status == HTTP_UNAUTHORIZED))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

    if ((static_cast<AuthDigestConfig*>(digestScheme::GetInstance()->getConfig())->authenticate) && authDigestNonceLastRequest(nonce)) {
        debugs(29, 9, "authDigestAddTrailer: Sending type:" << type << " header: 'nextnonce=\"" << authenticateDigestNonceNonceb64(nonce) << "\"");
        httpTrailerPutStrf(&rep->header, type, "nextnonce=\"%s\"", authenticateDigestNonceNonceb64(nonce));
    }
}
#endif

/* send the initial data to a digest authenticator module */
void
AuthDigestUserRequest::module_start(RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    char buf[8192];

    assert(user() != NULL && user()->auth_type == AUTH_DIGEST);
    debugs(29, 9, "authenticateStart: '\"" << user()->username() << "\":\"" << realm << "\"'");

    if (static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->authenticate == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Digest authentication program configured.");
        handler(data, NULL);
        return;
    }

    r = cbdataAlloc(authenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = static_cast<AuthUserRequest*>(this);
    if (static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->utf8) {
        char userstr[1024];
        latin1_to_utf8(userstr, sizeof(userstr), user()->username());
        snprintf(buf, 8192, "\"%s\":\"%s\"\n", userstr, realm);
    } else {
        snprintf(buf, 8192, "\"%s\":\"%s\"\n", user()->username(), realm);
    }

    helperSubmit(digestauthenticators, buf, AuthDigestUserRequest::HandleReply, r);
}

void
AuthDigestUserRequest::HandleReply(void *data, char *reply)
{
    authenticateStateData *replyData = static_cast < authenticateStateData * >(data);
    char *t = NULL;
    void *cbdata;
    debugs(29, 9, HERE << "{" << (reply ? reply : "<NULL>") << "}");

    if (reply) {
        if ((t = strchr(reply, ' ')))
            *t++ = '\0';

        if (*reply == '\0' || *reply == '\n')
            reply = NULL;
    }

    assert(replyData->auth_user_request != NULL);
    AuthUserRequest::Pointer auth_user_request = replyData->auth_user_request;

    if (reply && (strncasecmp(reply, "ERR", 3) == 0)) {
        /* allow this because the digest_request pointer is purely local */
        AuthDigestUserRequest *digest_request = dynamic_cast<AuthDigestUserRequest *>(auth_user_request.getRaw());
        assert(digest_request);

        digest_request->user()->credentials(AuthUser::Failed);
        digest_request->flags.invalid_password = 1;

        if (t && *t)
            digest_request->setDenyMessage(t);
    } else if (reply) {
        /* allow this because the digest_request pointer is purely local */
        DigestUser *digest_user = dynamic_cast<DigestUser *>(auth_user_request->user().getRaw());
        assert(digest_user != NULL);

        CvtBin(reply, digest_user->HA1);
        digest_user->HA1created = 1;
    }

    if (cbdataReferenceValidDone(replyData->data, &cbdata))
        replyData->handler(cbdata, NULL);

    replyData->auth_user_request = NULL;

    cbdataFree(replyData);
}
