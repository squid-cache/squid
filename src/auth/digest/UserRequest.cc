/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "auth/digest/Config.h"
#include "auth/digest/User.h"
#include "auth/digest/UserRequest.h"
#include "auth/State.h"
#include "charset.h"
#include "format/Format.h"
#include "helper.h"
#include "helper/Reply.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "SquidTime.h"

Auth::Digest::UserRequest::UserRequest() :
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
{
    memset(nc, 0, sizeof(nc));
    memset(&flags, 0, sizeof(flags));
}

/**
 * Delete the digest request structure.
 * Does NOT delete related AuthUser structures
 */
Auth::Digest::UserRequest::~UserRequest()
{
    assert(LockCount()==0);

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
Auth::Digest::UserRequest::authenticated() const
{
    if (user() != NULL && user()->credentials() == Auth::Ok)
        return 1;

    return 0;
}

const char *
Auth::Digest::UserRequest::credentialsStr()
{
    return realm;
}

/** log a digest user in
 */
void
Auth::Digest::UserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
{
    HASHHEX SESSIONKEY;
    HASHHEX HA2 = "";
    HASHHEX Response;

    /* if the check has corrupted the user, just return */
    if (user() == NULL || user()->credentials() == Auth::Failed) {
        return;
    }

    Auth::User::Pointer auth_user = user();

    Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User*>(auth_user.getRaw());
    assert(digest_user != NULL);

    Auth::Digest::UserRequest *digest_request = this;

    /* do we have the HA1 */
    if (!digest_user->HA1created) {
        auth_user->credentials(Auth::Pending);
        return;
    }

    if (digest_request->nonce == NULL) {
        /* this isn't a nonce we issued */
        auth_user->credentials(Auth::Failed);
        return;
    }

    DigestCalcHA1(digest_request->algorithm, NULL, NULL, NULL,
                  authenticateDigestNonceNonceb64(digest_request->nonce),
                  digest_request->cnonce,
                  digest_user->HA1, SESSIONKEY);
    SBuf sTmp = request->method.image();
    DigestCalcResponse(SESSIONKEY, authenticateDigestNonceNonceb64(digest_request->nonce),
                       digest_request->nc, digest_request->cnonce, digest_request->qop,
                       sTmp.c_str(), digest_request->uri, HA2, Response);

    debugs(29, 9, "\nResponse = '" << digest_request->response << "'\nsquid is = '" << Response << "'");

    if (strcasecmp(digest_request->response, Response) != 0) {
        if (!digest_request->flags.helper_queried) {
            /* Query the helper in case the password has changed */
            digest_request->flags.helper_queried = true;
            auth_user->credentials(Auth::Pending);
            return;
        }

        if (static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->PostWorkaround && request->method != Http::METHOD_GET) {
            /* Ugly workaround for certain very broken browsers using the
             * wrong method to calculate the request-digest on POST request.
             * This should be deleted once Digest authentication becomes more
             * widespread and such broken browsers no longer are commonly
             * used.
             */
            sTmp = HttpRequestMethod(Http::METHOD_GET).image();
            DigestCalcResponse(SESSIONKEY, authenticateDigestNonceNonceb64(digest_request->nonce),
                               digest_request->nc, digest_request->cnonce, digest_request->qop,
                               sTmp.c_str(), digest_request->uri, HA2, Response);

            if (strcasecmp(digest_request->response, Response)) {
                auth_user->credentials(Auth::Failed);
                digest_request->flags.invalid_password = true;
                digest_request->setDenyMessage("Incorrect password");
                return;
            } else {
                const char *useragent = request->header.getStr(HDR_USER_AGENT);

                static Ip::Address last_broken_addr;
                static int seen_broken_client = 0;

                if (!seen_broken_client) {
                    last_broken_addr.setNoAddr();
                    seen_broken_client = 1;
                }

                if (last_broken_addr != request->client_addr) {
                    debugs(29, DBG_IMPORTANT, "Digest POST bug detected from " <<
                           request->client_addr << " using '" <<
                           (useragent ? useragent : "-") <<
                           "'. Please upgrade browser. See Bug #630 for details.");

                    last_broken_addr = request->client_addr;
                }
            }
        } else {
            auth_user->credentials(Auth::Failed);
            digest_request->flags.invalid_password = true;
            digest_request->setDenyMessage("Incorrect password");
            return;
        }
    }

    /* check for stale nonce */
    /* check Auth::Pending to avoid loop */

    if (!authDigestNonceIsValid(digest_request->nonce, digest_request->nc) && user()->credentials() != Auth::Pending) {
        debugs(29, 3, auth_user->username() << "' validated OK but nonce stale: " << digest_request->nonceb64);
        /* Pending prevent banner and makes a ldap control */
        auth_user->credentials(Auth::Pending);
        nonce->flags.valid = false;
        authDigestNoncePurge(nonce);
        return;
    }

    auth_user->credentials(Auth::Ok);

    /* password was checked and did match */
    debugs(29, 4, HERE << "user '" << auth_user->username() << "' validated OK");

    /* auth_user is now linked, we reset these values
     * after external auth occurs anyway */
    auth_user->expiretime = current_time.tv_sec;
    return;
}

Auth::Direction
Auth::Digest::UserRequest::module_direction()
{
    if (user()->auth_type != Auth::AUTH_DIGEST)
        return Auth::CRED_ERROR;

    switch (user()->credentials()) {

    case Auth::Ok:
        return Auth::CRED_VALID;

    case Auth::Handshake:
    case Auth::Failed:
        /* send new challenge */
        return Auth::CRED_CHALLENGE;

    case Auth::Unchecked:
    case Auth::Pending:
        return Auth::CRED_LOOKUP;

    default:
        return Auth::CRED_ERROR;
    }
}

void
Auth::Digest::UserRequest::addAuthenticationInfoHeader(HttpReply * rep, int accel)
{
    http_hdr_type type;

    /* don't add to authentication error pages */
    if ((!accel && rep->sline.status() == Http::scProxyAuthenticationRequired)
            || (accel && rep->sline.status() == Http::scUnauthorized))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

#if WAITING_FOR_TE
    /* test for http/1.1 transfer chunked encoding */
    if (chunkedtest)
        return;
#endif

    if ((static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->authenticateProgram) && authDigestNonceLastRequest(nonce)) {
        flags.authinfo_sent = true;
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(user().getRaw());
        if (!digest_user)
            return;

        digest_nonce_h *nextnonce = digest_user->currentNonce();
        if (!nextnonce || authDigestNonceLastRequest(nonce)) {
            nextnonce = authenticateDigestNonceNew();
            authDigestUserLinkNonce(digest_user, nextnonce);
        }
        debugs(29, 9, "Sending type:" << type << " header: 'nextnonce=\"" << authenticateDigestNonceNonceb64(nextnonce) << "\"");
        httpHeaderPutStrf(&rep->header, type, "nextnonce=\"%s\"", authenticateDigestNonceNonceb64(nextnonce));
    }
}

#if WAITING_FOR_TE
void
Auth::Digest::UserRequest::addAuthenticationInfoTrailer(HttpReply * rep, int accel)
{
    int type;

    if (!auth_user_request)
        return;

    /* has the header already been send? */
    if (flags.authinfo_sent)
        return;

    /* don't add to authentication error pages */
    if ((!accel && rep->sline.status() == Http::scProxyAuthenticationRequired)
            || (accel && rep->sline.status() == Http::scUnauthorized))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

    if ((static_cast<Auth::Digest::Config*>(digestScheme::GetInstance()->getConfig())->authenticate) && authDigestNonceLastRequest(nonce)) {
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(auth_user_request->user().getRaw());
        nonce = digest_user->currentNonce();
        if (!nonce) {
            nonce = authenticateDigestNonceNew();
            authDigestUserLinkNonce(digest_user, nonce);
        }
        debugs(29, 9, "Sending type:" << type << " header: 'nextnonce=\"" << authenticateDigestNonceNonceb64(nonce) << "\"");
        httpTrailerPutStrf(&rep->header, type, "nextnonce=\"%s\"", authenticateDigestNonceNonceb64(nonce));
    }
}
#endif

/* send the initial data to a digest authenticator module */
void
Auth::Digest::UserRequest::startHelperLookup(HttpRequest *request, AccessLogEntry::Pointer &al, AUTHCB * handler, void *data)
{
    char buf[8192];

    assert(user() != NULL && user()->auth_type == Auth::AUTH_DIGEST);
    debugs(29, 9, HERE << "'\"" << user()->username() << "\":\"" << realm << "\"'");

    if (static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Digest authentication program configured.");
        handler(data);
        return;
    }

    const char *keyExtras = helperRequestKeyExtras(request, al);
    if (static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->utf8) {
        char userstr[1024];
        latin1_to_utf8(userstr, sizeof(userstr), user()->username());
        if (keyExtras)
            snprintf(buf, 8192, "\"%s\":\"%s\" %s\n", userstr, realm, keyExtras);
        else
            snprintf(buf, 8192, "\"%s\":\"%s\"\n", userstr, realm);
    } else {
        if (keyExtras)
            snprintf(buf, 8192, "\"%s\":\"%s\" %s\n", user()->username(), realm, keyExtras);
        else
            snprintf(buf, 8192, "\"%s\":\"%s\"\n", user()->username(), realm);
    }

    helperSubmit(digestauthenticators, buf, Auth::Digest::UserRequest::HandleReply,
                 new Auth::StateData(this, handler, data));
}

void
Auth::Digest::UserRequest::HandleReply(void *data, const Helper::Reply &reply)
{
    Auth::StateData *replyData = static_cast<Auth::StateData *>(data);
    debugs(29, 9, HERE << "reply=" << reply);

    assert(replyData->auth_user_request != NULL);
    Auth::UserRequest::Pointer auth_user_request = replyData->auth_user_request;

    // add new helper kv-pair notes to the credentials object
    // so that any transaction using those credentials can access them
    auth_user_request->user()->notes.appendNewOnly(&reply.notes);
    // remove any private credentials detail which got added.
    auth_user_request->user()->notes.remove("ha1");

    static bool oldHelperWarningDone = false;
    switch (reply.result) {
    case Helper::Unknown: {
        // Squid 3.3 and older the digest helper only returns a HA1 hash (no "OK")
        // the HA1 will be found in content() for these responses.
        if (!oldHelperWarningDone) {
            debugs(29, DBG_IMPORTANT, "WARNING: Digest auth helper returned old format HA1 response. It needs to be upgraded.");
            oldHelperWarningDone=true;
        }

        /* allow this because the digest_request pointer is purely local */
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(auth_user_request->user().getRaw());
        assert(digest_user != NULL);

        CvtBin(reply.other().content(), digest_user->HA1);
        digest_user->HA1created = 1;
    }
    break;

    case Helper::Okay: {
        /* allow this because the digest_request pointer is purely local */
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(auth_user_request->user().getRaw());
        assert(digest_user != NULL);

        const char *ha1Note = reply.notes.findFirst("ha1");
        if (ha1Note != NULL) {
            CvtBin(ha1Note, digest_user->HA1);
            digest_user->HA1created = 1;
        } else {
            debugs(29, DBG_IMPORTANT, "ERROR: Digest auth helper did not produce a HA1. Using the wrong helper program? received: " << reply);
        }
    }
    break;

    case Helper::TT:
        debugs(29, DBG_IMPORTANT, "ERROR: Digest auth does not support the result code received. Using the wrong helper program? received: " << reply);
    // fall through to next case. Handle this as an ERR response.

    case Helper::BrokenHelper:
    // TODO retry the broken lookup on another helper?
    // fall through to next case for now. Handle this as an ERR response silently.

    case Helper::Error: {
        /* allow this because the digest_request pointer is purely local */
        Auth::Digest::UserRequest *digest_request = dynamic_cast<Auth::Digest::UserRequest *>(auth_user_request.getRaw());
        assert(digest_request);

        digest_request->user()->credentials(Auth::Failed);
        digest_request->flags.invalid_password = true;

        const char *msgNote = reply.notes.find("message");
        if (msgNote != NULL) {
            digest_request->setDenyMessage(msgNote);
        } else if (reply.other().hasContent()) {
            // old helpers did send ERR result but a bare message string instead of message= key name.
            digest_request->setDenyMessage(reply.other().content());
            if (!oldHelperWarningDone) {
                debugs(29, DBG_IMPORTANT, "WARNING: Digest auth helper returned old format ERR response. It needs to be upgraded.");
                oldHelperWarningDone=true;
            }
        }
    }
    break;
    }

    void *cbdata = NULL;
    if (cbdataReferenceValidDone(replyData->data, &cbdata))
        replyData->handler(cbdata);

    delete replyData;
}

