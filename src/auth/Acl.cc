/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "auth/Acl.h"
#include "auth/AclProxyAuth.h"
#include "auth/UserRequest.h"
#include "client_side.h"
#include "fatal.h"
#include "http/Stream.h"
#include "HttpRequest.h"

/**
 * \retval ACCESS_AUTH_REQUIRED credentials missing. challenge required.
 * \retval ACCESS_DENIED        user not authenticated (authentication error?)
 * \retval ACCESS_DUNNO         user authentication is in progress
 * \retval ACCESS_DENIED        user not authorized
 * \retval ACCESS_ALLOWED       user authenticated and authorized
 */
Acl::Answer
AuthenticateAcl(ACLChecklist *ch, const Acl::Node &acl)
{
    ACLFilledChecklist *checklist = Filled(ch);
    const auto request = checklist->request;
    Http::HdrType headertype;

    if (!request) {
        fatal ("requiresRequest SHOULD have been true for this ACL!!");
        return ACCESS_DENIED;
    } else if (request->flags.sslBumped) {
        debugs(28, 5, "SslBumped request: It is an encapsulated request do not authenticate");
        checklist->auth_user_request = checklist->conn() != nullptr ? checklist->conn()->getAuth() : request->auth_user_request;
        if (checklist->auth_user_request != nullptr)
            return ACCESS_ALLOWED;
        else
            return ACCESS_DENIED;
    } else if (request->flags.accelerated) {
        /* WWW authorization on accelerated requests */
        headertype = Http::HdrType::AUTHORIZATION;
    } else if (request->flags.intercepted || request->flags.interceptTproxy) {
        debugs(28, DBG_IMPORTANT, "WARNING: Authentication not applicable on intercepted requests.");
        return ACCESS_DENIED;
    } else {
        /* Proxy authorization on proxy requests */
        headertype = Http::HdrType::PROXY_AUTHORIZATION;
    }

    /* get authed here */
    /* Note: this fills in auth_user_request when applicable */
    const AuthAclState result = Auth::UserRequest::tryToAuthenticateAndSetAuthUser(
                                    &checklist->auth_user_request, headertype, checklist->request.getRaw(),
                                    checklist->conn(), checklist->src_addr, checklist->al);
    switch (result) {

    case AUTH_ACL_CANNOT_AUTHENTICATE:
        debugs(28, 4, "returning " << ACCESS_DENIED << " user authenticated but not authorised.");
        return ACCESS_DENIED;

    case AUTH_AUTHENTICATED:
        return ACCESS_ALLOWED;
        break;

    case AUTH_ACL_HELPER:
        if (checklist->goAsync(ACLProxyAuth::StartLookup, acl))
            debugs(28, 4, "returning " << ACCESS_DUNNO << " sending credentials to helper.");
        else
            debugs(28, 2, "cannot go async; returning " << ACCESS_DUNNO);
        return ACCESS_DUNNO; // XXX: break this down into DUNNO, EXPIRED_OK, EXPIRED_BAD states

    case AUTH_ACL_CHALLENGE:
        debugs(28, 4, "returning " << ACCESS_AUTH_REQUIRED << " sending authentication challenge.");
        /* Client is required to resend the request with correct authentication
         * credentials. (This may be part of a stateful auth protocol.)
         * The request is denied.
         */
        return ACCESS_AUTH_REQUIRED;

    default:
        fatal("unexpected authenticateAuthenticate reply\n");
        return ACCESS_DENIED;
    }
}

