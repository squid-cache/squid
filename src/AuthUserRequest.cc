
/*
 * $Id: AuthUserRequest.cc,v 1.16 2007/05/09 09:07:38 wessels Exp $
 *
 * DO NOT MODIFY NEXT 2 LINES:
 * arch-tag: 6803fde1-d5a2-4c29-9034-1c0c9f650eb4
 *
 * DEBUG: section 29    Authenticator
 * AUTHOR:  Robert Collins
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "AuthUserRequest.h"
#include "AuthUser.h"
/*#include "authenticate.h"
#include "ACL.h"
#include "client_side.h"
*/
#include "AuthConfig.h"
#include "AuthScheme.h"
#include "HttpReply.h"
#include "HttpRequest.h"

/* Generic Functions */

size_t
AuthUserRequest::refCount () const
{
    return references;
}

char const *
AuthUserRequest::username() const
{
    if (user())
        return user()->username();
    else
        return NULL;
}

size_t
authenticateRequestRefCount (AuthUserRequest *aRequest)
{
    return aRequest->refCount();
}

/**** PUBLIC FUNCTIONS (ALL GENERIC!)  ****/

/* send the initial data to an authenticator module */
void
AuthUserRequest::start(RH * handler, void *data)
{
    assert(handler);
    debugs(29, 9, "authenticateStart: auth_user_request '" << this << "'");
    module_start(handler, data);
}

/*
 * Check a auth_user pointer for validity. Does not check passwords, just data
 * sensability. Broken or Unknown auth_types are not valid for use...
 */

int
authenticateValidateUser(AuthUserRequest * auth_user_request)
{
    debugs(29, 9, "authenticateValidateUser: Validating Auth_user request '" << auth_user_request << "'.");

    if (auth_user_request == NULL) {
        debugs(29, 4, "authenticateValidateUser: Auth_user_request was NULL!");
        return 0;
    }

    if (auth_user_request->user() == NULL) {
        debugs(29, 4, "authenticateValidateUser: No associated auth_user structure");
        return 0;
    }

    if (auth_user_request->user()->auth_type == AUTH_UNKNOWN) {
        debugs(29, 4, "authenticateValidateUser: Auth_user '" << auth_user_request->user() << "' uses unknown scheme.");
        return 0;
    }

    if (auth_user_request->user()->auth_type == AUTH_BROKEN) {
        debugs(29, 4, "authenticateValidateUser: Auth_user '" << auth_user_request->user() << "' is broken for it's scheme.");
        return 0;
    }

    /* any other sanity checks that we need in the future */

    /* Thus should a module call to something like authValidate */

    /* finally return ok */
    debugs(29, 5, "authenticateValidateUser: Validated Auth_user request '" << auth_user_request << "'.");

    return 1;

}

void *
AuthUserRequest::operator new (size_t byteCount)
{
    fatal ("AuthUserRequest not directly allocatable\n");
    return (void *)1;
}

void
AuthUserRequest::operator delete (void *address)
{
    fatal ("AuthUserRequest child failed to override operator delete\n");
}

AuthUserRequest::AuthUserRequest():_auth_user(NULL), message(NULL),
        references (0), lastReply (AUTH_ACL_CANNOT_AUTHENTICATE)
{
    debugs(29, 5, "AuthUserRequest::AuthUserRequest: initialised request " <<
           this);
}

AuthUserRequest::~AuthUserRequest()
{
    dlink_node *link;
    debugs(29, 5, "AuthUserRequest::~AuthUserRequest: freeing request " <<
           this);
    assert(references == 0);

    if (user()) {
        /* unlink from the auth_user struct */
        link = user()->requests.head;

        while (link && (link->data != this))
            link = link->next;

        assert(link != NULL);

        dlinkDelete(link, &user()->requests);

        dlinkNodeDelete(link);

        /* unlock the request structure's lock */
        user()->unlock();

        user(NULL);
    }

    safe_free (message);
}

void
AuthUserRequest::setDenyMessage (char const *aString)
{
    safe_free (message);
    message = xstrdup (aString);
}

char const *
AuthUserRequest::getDenyMessage ()
{
    return message;
}

char const *
AuthUserRequest::denyMessage(char const * const default_message)
{
    if (this == NULL || getDenyMessage() == NULL) {
        return default_message;
    }

    return getDenyMessage();
}

static void
authenticateAuthUserRequestSetIp(AuthUserRequest * auth_user_request, struct IN_ADDR ipaddr)
{
    auth_user_t *auth_user = auth_user_request->user();

    if (!auth_user)
        return;

    auth_user->addIp(ipaddr);
}

void
authenticateAuthUserRequestRemoveIp(AuthUserRequest * auth_user_request, struct IN_ADDR ipaddr)
{
    auth_user_t *auth_user = auth_user_request->user();

    if (!auth_user)
        return;

    auth_user->removeIp(ipaddr);
}

void
authenticateAuthUserRequestClearIp(AuthUserRequest * auth_user_request)
{
    if (auth_user_request)
        auth_user_request->user()->clearIp();
}

int
authenticateAuthUserRequestIPCount(AuthUserRequest * auth_user_request)
{
    assert(auth_user_request);
    assert(auth_user_request->user());
    return auth_user_request->user()->ipcount;
}


/*
 * authenticateUserAuthenticated: is this auth_user structure logged in ?
 */
int
authenticateUserAuthenticated(AuthUserRequest * auth_user_request)
{
    if (!authenticateValidateUser(auth_user_request))
        return 0;

    return auth_user_request->authenticated();
}

int
AuthUserRequest::direction()
{
    if (authenticateUserAuthenticated(this))
        return 0;

    return module_direction();

    return -2;
}

void
AuthUserRequest::addHeader(HttpReply * rep, int accelerated)
{}

void
AuthUserRequest::addTrailer(HttpReply * rep, int accelerated)
{}

void
AuthUserRequest::onConnectionClose(ConnStateData *)
{}

const char *
AuthUserRequest::connLastHeader()
{
    fatal("AuthUserRequest::connLastHeader should always be overridden by conn based auth schemes");
    return NULL;
}

/*
 * authenticateAuthenticateUser: call the module specific code to 
 * log this user request in.
 * Cache hits may change the auth_user pointer in the structure if needed.
 * This is basically a handle approach.
 */
static void
authenticateAuthenticateUser(AuthUserRequest * auth_user_request, HttpRequest * request, ConnStateData::Pointer &conn, http_hdr_type type)
{
    assert(auth_user_request != NULL);

    auth_user_request->authenticate(request, conn, type);
}

static AuthUserRequest *
authTryGetUser (AuthUserRequest **auth_user_request, ConnStateData::Pointer & conn, HttpRequest * request)
{
    if (*auth_user_request)
        return *auth_user_request;
    else if (request != NULL && request->auth_user_request)
        return request->auth_user_request;
    else if (conn != NULL)
        return conn->auth_user_request;
    else
        return NULL;
}

/* returns one of
 * AUTH_ACL_CHALLENGE,
 * AUTH_ACL_HELPER,
 * AUTH_ACL_CANNOT_AUTHENTICATE,
 * AUTH_AUTHENTICATED
 *
 * How to use: In your proxy-auth dependent acl code, use the following 
 * construct:
 * int rv;
 * if ((rv = AuthenticateAuthenticate()) != AUTH_AUTHENTICATED)
 *   return rv;
 * 
 * when this code is reached, the request/connection is authenticated.
 *
 * if you have non-acl code, but want to force authentication, you need a 
 * callback mechanism like the acl testing routines that will send a 40[1|7] to
 * the client when rv==AUTH_ACL_CHALLENGE, and will communicate with 
 * the authenticateStart routine for rv==AUTH_ACL_HELPER
 *
 * Caller is responsible for locking and unlocking their *auth_user_request!
 */
auth_acl_t

AuthUserRequest::authenticate(AuthUserRequest ** auth_user_request, http_hdr_type headertype, HttpRequest * request, ConnStateData::Pointer conn, struct IN_ADDR src_addr)
{
    const char *proxy_auth;
    assert(headertype != 0);

    proxy_auth = request->header.getStr(headertype);

    /*
     * a note on proxy_auth logix here:
     * proxy_auth==NULL -> unauthenticated request || already
     * authenticated connection so we test for an authenticated
     * connection when we recieve no authentication header.
     */

    if (((proxy_auth == NULL) && (!authenticateUserAuthenticated(authTryGetUser(auth_user_request,conn,request))))
            || (conn != NULL  && conn->auth_type == AUTH_BROKEN))
    {
        /* no header or authentication failed/got corrupted - restart */
        debugs(29, 4, "authenticateAuthenticate: broken auth or no proxy_auth header. Requesting auth header.");
        /* something wrong with the AUTH credentials. Force a new attempt */

        if (conn != NULL) {
            conn->auth_type = AUTH_UNKNOWN;
	    AUTHUSERREQUESTUNLOCK(conn->auth_user_request, "conn");
        }

	*auth_user_request = NULL;
        return AUTH_ACL_CHALLENGE;
    }

    /*
     * Is this an already authenticated connection with a new auth header?
     * No check for function required in the if: its compulsory for conn based 
     * auth modules
     */
    if (proxy_auth && conn != NULL && conn->auth_user_request &&
            authenticateUserAuthenticated(conn->auth_user_request) &&
            conn->auth_user_request->connLastHeader() != NULL &&
            strcmp(proxy_auth, conn->auth_user_request->connLastHeader()))
    {
        debugs(29, 2, "authenticateAuthenticate: DUPLICATE AUTH - authentication header on already authenticated connection!. AU " <<
               conn->auth_user_request << ", Current user '" <<
               conn->auth_user_request->username() << "' proxy_auth " <<
               proxy_auth);

        /* remove this request struct - the link is already authed and it can't be to
         * reauth.
         */

        /* This should _only_ ever occur on the first pass through
         * authenticateAuthenticate 
         */
        assert(*auth_user_request == NULL);
	AUTHUSERREQUESTUNLOCK(conn->auth_user_request, "conn");
        /* Set the connection auth type */
        conn->auth_type = AUTH_UNKNOWN;
    }

    /* we have a proxy auth header and as far as we know this connection has
     * not had bungled connection oriented authentication happen on it. */
    debugs(29, 9, "authenticateAuthenticate: header " << (proxy_auth ? proxy_auth : "-") << ".");

    if (*auth_user_request == NULL)
    {
        debugs(29, 9, "authenticateAuthenticate: This is a new checklist test on FD:" << (conn != NULL ? conn->fd : -1)  );

        if (proxy_auth && !request->auth_user_request && conn != NULL && conn->auth_user_request) {
            AuthConfig * scheme = AuthConfig::Find(proxy_auth);

            if (!conn->auth_user_request->user() || conn->auth_user_request->user()->config != scheme) {
                debugs(29, 1, "authenticateAuthenticate: Unexpected change of authentication scheme from '" <<
                       conn->auth_user_request->user()->config->type() <<
                       "' to '" << proxy_auth << "' (client " <<
                       inet_ntoa(src_addr) << ")");

		AUTHUSERREQUESTUNLOCK(conn->auth_user_request, "conn");
                conn->auth_type = AUTH_UNKNOWN;
            }
        }

        if ((!request->auth_user_request)
                && (conn == NULL || conn->auth_type == AUTH_UNKNOWN)) {
            /* beginning of a new request check */
            debugs(29, 4, "authenticateAuthenticate: no connection authentication type");

	    *auth_user_request = AuthConfig::CreateAuthUser(proxy_auth);
            if (!authenticateValidateUser(*auth_user_request)) {
                if (*auth_user_request == NULL)
                    return AUTH_ACL_CHALLENGE;

                /* the decode might have left a username for logging, or a message to
                 * the user */

                if ((*auth_user_request)->username()) {
                    request->auth_user_request = *auth_user_request;
		    AUTHUSERREQUESTLOCK(request->auth_user_request, "request");
                }

                *auth_user_request = NULL;
                return AUTH_ACL_CHALLENGE;
            }

            /* the user_request comes prelocked for the caller to createAuthUser (us) */
        } else if (request->auth_user_request) {
            *auth_user_request = request->auth_user_request;
        } else {
            assert (conn != NULL);
            if (conn->auth_user_request) {
                *auth_user_request = conn->auth_user_request;
            } else {
                /* failed connection based authentication */
                debugs(29, 4, "authenticateAuthenticate: Auth user request " <<
                       *auth_user_request << " conn-auth user request " <<
                       conn->auth_user_request << " conn type " <<
                       conn->auth_type << " authentication failed.");

                *auth_user_request = NULL;
                return AUTH_ACL_CHALLENGE;
            }
        }
    }

    if (!authenticateUserAuthenticated(*auth_user_request))
    {
        /* User not logged in. Log them in */
        authenticateAuthenticateUser(*auth_user_request, request,
                                     conn, headertype);

        switch (authenticateDirection(*auth_user_request)) {

        case 1:

            if (NULL == request->auth_user_request) {
                request->auth_user_request = *auth_user_request;
		AUTHUSERREQUESTLOCK(request->auth_user_request, "request");
            }

            /* fallthrough to -2 */

        case -2:
            /* this ACL check is finished. */
            *auth_user_request = NULL;
            return AUTH_ACL_CHALLENGE;

        case -1:
            /* we are partway through authentication within squid,
             * the *auth_user_request variables stores the auth_user_request
             * for the callback to here - Do not Unlock */
            return AUTH_ACL_HELPER;
        }

        /* on 0 the authentication is finished - fallthrough */
        /* See if user authentication failed for some reason */
        if (!authenticateUserAuthenticated(*auth_user_request)) {
            if ((*auth_user_request)->username()) {
                if (!request->auth_user_request) {
                    request->auth_user_request = *auth_user_request;
		    AUTHUSERREQUESTLOCK(request->auth_user_request, "request");
                }
            }

            *auth_user_request = NULL;
            return AUTH_ACL_CHALLENGE;
        }
    }

    /* copy username to request for logging on client-side */
    /* the credentials are correct at this point */
    if (NULL == request->auth_user_request) {
        request->auth_user_request = *auth_user_request;
	AUTHUSERREQUESTLOCK(request->auth_user_request, "request");
        authenticateAuthUserRequestSetIp(*auth_user_request, src_addr);
    }

    return AUTH_AUTHENTICATED;
}

auth_acl_t

AuthUserRequest::tryToAuthenticateAndSetAuthUser(AuthUserRequest ** auth_user_request, http_hdr_type headertype, HttpRequest * request, ConnStateData::Pointer conn, struct IN_ADDR src_addr)
{
    /* If we have already been called, return the cached value */
    AuthUserRequest *t = authTryGetUser (auth_user_request, conn, request);

    if (t && t->lastReply != AUTH_ACL_CANNOT_AUTHENTICATE
            && t->lastReply != AUTH_ACL_HELPER)
    {
        if (!*auth_user_request)
            *auth_user_request = t;

	if (!request->auth_user_request && t->lastReply == AUTH_AUTHENTICATED) {
	    request->auth_user_request = t;
	    AUTHUSERREQUESTLOCK(request->auth_user_request, "request");
	}
        return t->lastReply;
    }

    /* ok, call the actual authenticator routine. */
    auth_acl_t result = authenticate(auth_user_request, headertype, request, conn, src_addr);

    t = authTryGetUser (auth_user_request, conn, request);

    if (t && result != AUTH_ACL_CANNOT_AUTHENTICATE &&
            result != AUTH_ACL_HELPER)
        t->lastReply = result;

    return result;
}

/* returns
 * 0: no output needed
 * 1: send to client
 * -1: send to helper
 * -2: authenticate broken in some fashion
 */
int
authenticateDirection(AuthUserRequest * auth_user_request)
{
    if (!auth_user_request)
        return -2;

    return auth_user_request->direction();
}

void
AuthUserRequest::addReplyAuthHeader(HttpReply * rep, AuthUserRequest * auth_user_request, HttpRequest * request, int accelerated, int internal)
/* send the auth types we are configured to support (and have compiled in!) */
{
    http_hdr_type type;

    switch (rep->sline.status)
    {

    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
        /* Proxy authorisation needed */
        type = HDR_PROXY_AUTHENTICATE;
        break;

    case HTTP_UNAUTHORIZED:
        /* WWW Authorisation needed */
        type = HDR_WWW_AUTHENTICATE;
        break;

    default:
        /* Keep GCC happy */
        /* some other HTTP status */
        type = HDR_ENUM_END;
        break;
    }

    debugs(29, 9, "authenticateFixHeader: headertype:" << type << " authuser:" << auth_user_request);

    if (((rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (rep->sline.status == HTTP_UNAUTHORIZED)) && internal)
        /* this is a authenticate-needed response */
    {

        if ((auth_user_request != NULL) && !authenticateUserAuthenticated(auth_user_request))
            /* scheme specific */
            auth_user_request->user()->config->fixHeader(auth_user_request, rep, type, request);
        else
        {
            /* call each configured & running authscheme */

            for (authConfig::iterator  i = Config.authConfiguration.begin(); i != Config.authConfiguration.end(); ++i) {
                AuthConfig *scheme = *i;

                if (scheme->active())
                    scheme->fixHeader(NULL, rep, type, request);
                else
                    debugs(29, 4, "authenticateFixHeader: Configured scheme " << scheme->type() << " not Active");
            }
        }

    }
    /*
     * allow protocol specific headers to be _added_ to the existing
     * response - ie digest auth
     */

    if (auth_user_request != NULL)
    {
        auth_user_request->addHeader(rep, accelerated);
	if (auth_user_request->lastReply != AUTH_AUTHENTICATED)
	    auth_user_request->lastReply = AUTH_ACL_CANNOT_AUTHENTICATE;
    }
}

void
authenticateFixHeader(HttpReply * rep, AuthUserRequest * auth_user_request, HttpRequest * request, int accelerated, int internal)
{
    AuthUserRequest::addReplyAuthHeader(rep, auth_user_request, request, accelerated, internal);
}


/* call the active auth module and allow it to add a trailer to the request */
void
authenticateAddTrailer(HttpReply * rep, AuthUserRequest * auth_user_request, HttpRequest * request, int accelerated)
{
    if (auth_user_request != NULL)
        auth_user_request->addTrailer(rep, accelerated);
}

void

AuthUserRequest::_lock()
{
    assert(this);
    debugs(29, 9, "AuthUserRequest::lock: auth_user request '" << this << " " << references << "->" << references+1);
    ++references;
}

void
AuthUserRequest::_unlock()
{
    assert(this != NULL);

    if (references > 0) {
        debugs(29, 9, "AuthUserRequest::unlock: auth_user request '" << this << " " << references << "->" << references-1);
        --references;
    } else {
        debugs(29, 1, "Attempt to lower Auth User request " << this << " refcount below 0!");
    }

    if (references == 0) {
        debugs(29, 9, "AuthUserRequest::unlock: deleting auth_user_request '" << this << "'.");
        /* not locked anymore */
        delete this;
    }
}

AuthScheme *
AuthUserRequest::scheme() const
{
    /* TODO: this should be overriden by the child and be essentially a no-op */
    return AuthScheme::Find(user()->config->type());
}
