
/*
 * $Id: authenticate.cc,v 1.52 2003/02/12 06:11:00 robertc Exp $
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
#include "authenticate.h"
#include "ACL.h"

CBDATA_TYPE(auth_user_ip_t);

/*
 *
 * Private Data
 *
 */

MemPool *AuthUserRequest::pool = NULL;
MemPool *AuthUserHashPointer::pool = NULL;
MemPool *AuthUser::pool = NULL;
/*
 *     memDataInit(MEM_AUTH_USER_T, "auth_user_t",
 *             sizeof(auth_user_t), 0);
 */

/* Generic Functions */


static int
authenticateAuthSchemeConfigured(const char *proxy_auth)
{
    authScheme *scheme;
    int i;
    for (i = 0; i < Config.authConfiguration.n_configured; i++) {
	scheme = Config.authConfiguration.schemes + i;
	if ((strncasecmp(proxy_auth, scheme->typestr, strlen(scheme->typestr)) == 0) &&
	    (authscheme_list[scheme->Id].Active()))
	    return 1;
    }
    return 0;
}

int
authenticateAuthSchemeId(const char *typestr)
{
    int i = 0;
    for (i = 0; authscheme_list && authscheme_list[i].typestr; i++) {
	if (strncasecmp(typestr, authscheme_list[i].typestr, strlen(authscheme_list[i].typestr)) == 0) {
	    return i;
	}
    }
    return -1;
}

void
AuthUserRequest::decodeAuth(const char *proxy_auth)
{
    int i = 0;
    assert(proxy_auth != NULL);
    debug(29, 9) ("authenticateDecodeAuth: header = '%s'\n", proxy_auth);
    if (!authenticateAuthSchemeConfigured(proxy_auth) || 
	(i = authenticateAuthSchemeId(proxy_auth)) == -1) {
	debug(29, 1) ("AuthUserRequest::decodeAuth: Unsupported or unconfigured proxy-auth scheme, '%s'\n", proxy_auth);
	return;
    }
    assert (i >= 0);
    authscheme_list[i].decodeauth(this, proxy_auth);
    auth_user->auth_module = i + 1;
}

size_t
AuthUserRequest::refCount () const
{
    return references;
}

char const *
AuthUserRequest::username() const
{
    if (auth_user)
	return auth_user->username();
    else
	return NULL;
}

size_t
authenticateRequestRefCount (auth_user_request_t *aRequest)
{
    return aRequest->refCount();
}

/* clear any connection related authentication details */
void
authenticateOnCloseConnection(ConnStateData * conn)
{
    auth_user_request_t *auth_user_request;
    assert(conn != NULL);
    if (conn->auth_user_request != NULL) {
	auth_user_request = conn->auth_user_request;
	/* if the auth type gets reset, the connection shouldn't 
	 * remain linked to it - the next type might not be conn based
	 */
	assert(auth_user_request->auth_user->auth_module);
	if (authscheme_list[auth_user_request->auth_user->auth_module - 1].oncloseconnection) {
	    authscheme_list[auth_user_request->auth_user->auth_module - 1].oncloseconnection(conn);
	}
    }
}

/**** PUBLIC FUNCTIONS (ALL GENERIC!)  ****/

/* send the initial data to an authenticator module */
void
AuthUserRequest::start(RH * handler, void *data)
{
    assert(handler);
    debug(29, 9) ("authenticateStart: auth_user_request '%p'\n", this);
    if (auth_user->auth_module > 0)
	authscheme_list[auth_user->auth_module - 1].authStart(this, handler, data);
    else
	handler(data, NULL);
}

void
authenticateStart(auth_user_request_t * auth_user_request, RH * handler, void *data)
{
    assert(auth_user_request);
    auth_user_request->start (handler, data);
}

/*
 * Check a auth_user pointer for validity. Does not check passwords, just data
 * sensability. Broken or Unknown auth_types are not valid for use...
 */

int
authenticateValidateUser(auth_user_request_t * auth_user_request)
{
    debug(29, 9) ("authenticateValidateUser: Validating Auth_user request '%p'.\n", auth_user_request);
    if (auth_user_request == NULL) {
	debug(29, 4) ("authenticateValidateUser: Auth_user_request was NULL!\n");
	return 0;
    }
    if (auth_user_request->auth_user == NULL) {
	debug(29, 4) ("authenticateValidateUser: No associated auth_user structure\n");
	return 0;
    }
    if (auth_user_request->auth_user->auth_type == AUTH_UNKNOWN) {
	debug(29, 4) ("authenticateValidateUser: Auth_user '%p' uses unknown scheme.\n", auth_user_request->auth_user);
	return 0;
    }
    if (auth_user_request->auth_user->auth_type == AUTH_BROKEN) {
	debug(29, 4) ("authenticateValidateUser: Auth_user '%p' is broken for it's scheme.\n", auth_user_request->auth_user);
	return 0;
    }
    if (!auth_user_request->auth_user->scheme_data) {
	debug(29, 4) ("authenticateValidateUser: auth_user '%p' has no scheme data\n", auth_user_request->auth_user);
	return 0;
    }
    /* any other sanity checks that we need in the future */

    /* Thus should a module call to something like authValidate */

    /* finally return ok */
    debug(29, 5) ("authenticateValidateUser: Validated Auth_user request '%p'.\n", auth_user_request);
    return 1;

}

void *
AuthUser::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (AuthUser));
    if (!pool)
	pool = memPoolCreate("Authenticate User Data", sizeof (auth_user_t));
    return memPoolAlloc(pool);
}

AuthUser::AuthUser (const char *scheme) :
auth_type (AUTH_UNKNOWN), auth_module (authenticateAuthSchemeId(scheme) + 1),
usernamehash (NULL), ipcount (0), expiretime (0), references (0), scheme_data (NULL)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
    proxy_match_cache.head = proxy_match_cache.tail = NULL;
    ip_list.head = ip_list.tail = NULL;
    requests.head = requests.tail = NULL;
}

char const *
AuthUser::username () const
{
    if (auth_module <= 0)
	return NULL;
    return authscheme_list[auth_module - 1].authUserUsername(this);
}

auth_user_t *
authenticateAuthUserNew(const char *scheme)
{
    return new AuthUser (scheme);
}

void *
AuthUserRequest::operator new (size_t byteCount)
{
    /* derived classes with different sizes must implement their own new */
    assert (byteCount == sizeof (AuthUserRequest));
    if (!pool)
	pool = memPoolCreate("Authenticate Request Data", sizeof(auth_user_request_t));
    return static_cast<auth_user_request_t *>(memPoolAlloc(pool));
}

void
AuthUserRequest::operator delete (void *address)
{
    memPoolFree(pool, address);
}

AuthUserRequest::AuthUserRequest():auth_user(NULL), scheme_data (NULL), message(NULL),
  references (0), lastReply (AUTH_ACL_CANNOT_AUTHENTICATE)
{
}
 
AuthUserRequest::~AuthUserRequest()
{
    dlink_node *link;
    debug(29, 5) ("AuthUserRequest::~AuthUserRequest: freeing request %p\n", this);
    assert(references == 0);
    if (auth_user) {
	if (scheme_data != NULL) {
	    /* we MUST know the module */
	    assert(auth_user->auth_module > 0);
	    /* and the module MUST support requestFree if it has created scheme data */
	    assert(authscheme_list[auth_user->auth_module - 1].requestFree != NULL);
	    authscheme_list[auth_user->auth_module - 1].requestFree(this);
	}
	/* unlink from the auth_user struct */
	link = auth_user->requests.head;
	while (link && (link->data != this))
	    link = link->next;
	assert(link != NULL);
	dlinkDelete(link, &auth_user->requests);
	dlinkNodeDelete(link);

	/* unlock the request structure's lock */
	authenticateAuthUserUnlock(auth_user);
	auth_user = NULL;
    } else
	assert(scheme_data == NULL);
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
authenticateAuthUserRequestMessage(auth_user_request_t * auth_user_request)
{
    if (auth_user_request)
	return auth_user_request->getDenyMessage();
    return NULL;
}

void
authenticateSetDenyMessage (auth_user_request_t * auth_user_request, char const *message)
{
    auth_user_request->setDenyMessage (message);
}

static void
authenticateAuthUserRequestSetIp(auth_user_request_t * auth_user_request, struct in_addr ipaddr)
{
    auth_user_ip_t *ipdata, *tempnode;
    auth_user_t *auth_user;
    char *ip1;
    int found = 0;
    CBDATA_INIT_TYPE(auth_user_ip_t);
    if (!auth_user_request->auth_user)
	return;
    auth_user = auth_user_request->auth_user;
    ipdata = (auth_user_ip_t *) auth_user->ip_list.head;
    /*
     * we walk the entire list to prevent the first item in the list
     * preventing old entries being flushed and locking a user out after
     * a timeout+reconfigure
     */
    while (ipdata) {
	tempnode = (auth_user_ip_t *) ipdata->node.next;
	/* walk the ip list */
	if (ipdata->ipaddr.s_addr == ipaddr.s_addr) {
	    /* This ip has alreadu been seen. */
	    found = 1;
	    /* update IP ttl */
	    ipdata->ip_expiretime = squid_curtime;
	} else if (ipdata->ip_expiretime + Config.authenticateIpTTL < squid_curtime) {
	    /* This IP has expired - remove from the seen list */
	    dlinkDelete(&ipdata->node, &auth_user->ip_list);
	    cbdataFree(ipdata);
	    /* catch incipient underflow */
	    assert(auth_user->ipcount);
	    auth_user->ipcount--;
	}
	ipdata = tempnode;
    }

    if (found)
	return;

    /* This ip is not in the seen list */
    ipdata = cbdataAlloc(auth_user_ip_t);
    ipdata->ip_expiretime = squid_curtime;
    ipdata->ipaddr = ipaddr;
    dlinkAddTail(ipdata, &ipdata->node, &auth_user->ip_list);
    auth_user->ipcount++;

    ip1 = xstrdup(inet_ntoa(ipaddr));
    debug(29, 2) ("authenticateAuthUserRequestSetIp: user '%s' has been seen at a new IP address (%s)\n ", auth_user->username(), ip1);
    safe_free(ip1);
}

void
authenticateAuthUserRequestRemoveIp(auth_user_request_t * auth_user_request, struct in_addr ipaddr)
{
    auth_user_ip_t *ipdata;
    auth_user_t *auth_user;
    if (!auth_user_request->auth_user)
	return;
    auth_user = auth_user_request->auth_user;
    ipdata = (auth_user_ip_t *) auth_user->ip_list.head;
    while (ipdata) {
	/* walk the ip list */
	if (ipdata->ipaddr.s_addr == ipaddr.s_addr) {
	    /* remove the node */
	    dlinkDelete(&ipdata->node, &auth_user->ip_list);
	    cbdataFree(ipdata);
	    /* catch incipient underflow */
	    assert(auth_user->ipcount);
	    auth_user->ipcount--;
	    return;
	}
	ipdata = (auth_user_ip_t *) ipdata->node.next;
    }

}

static void
authenticateAuthUserClearIp(auth_user_t * auth_user)
{
    auth_user_ip_t *ipdata, *tempnode;
    if (!auth_user)
	return;
    ipdata = (auth_user_ip_t *) auth_user->ip_list.head;
    while (ipdata) {
	tempnode = (auth_user_ip_t *) ipdata->node.next;
	/* walk the ip list */
	dlinkDelete(&ipdata->node, &auth_user->ip_list);
	cbdataFree(ipdata);
	/* catch incipient underflow */
	assert(auth_user->ipcount);
	auth_user->ipcount--;
	ipdata = tempnode;
    }
    /* integrity check */
    assert(auth_user->ipcount == 0);
}


void
authenticateAuthUserRequestClearIp(auth_user_request_t * auth_user_request)
{
    if (auth_user_request)
	authenticateAuthUserClearIp(auth_user_request->auth_user);
}

size_t
authenticateAuthUserRequestIPCount(auth_user_request_t * auth_user_request)
{
    assert(auth_user_request);
    assert(auth_user_request->auth_user);
    return auth_user_request->auth_user->ipcount;
}


/* Get Auth User: Return a filled out auth_user structure for the given
 * Proxy Auth (or Auth) header. It may be a cached Auth User or a new
 * Unauthenticated structure. The structure is given an inital lock here.
 */
auth_user_request_t *
AuthUserRequest::createAuthUser(const char *proxy_auth)
{
    auth_user_request_t *result = new auth_user_request_t;
    /* and lock for the callers instance */
    result->lock();
    /* The scheme is allowed to provide a cached auth_user or a new one */
    result->decodeAuth(proxy_auth);
    return result;
}

/*
 * authenticateUserAuthenticated: is this auth_user structure logged in ?
 */
int
authenticateUserAuthenticated(auth_user_request_t * auth_user_request)
{
    if (!authenticateValidateUser(auth_user_request))
	return 0;
    if (auth_user_request->auth_user->auth_module > 0)
	return authscheme_list[auth_user_request->auth_user->auth_module - 1].authenticated(auth_user_request);
    else
	return 0;
}

/*
 * authenticateAuthenticateUser: call the module specific code to 
 * log this user request in.
 * Cache hits may change the auth_user pointer in the structure if needed.
 * This is basically a handle approach.
 */
static void
authenticateAuthenticateUser(auth_user_request_t * auth_user_request, request_t * request, ConnStateData * conn, http_hdr_type type)
{
    assert(auth_user_request != NULL);
    if (auth_user_request->auth_user->auth_module > 0)
	authscheme_list[auth_user_request->auth_user->auth_module - 1].authAuthenticate(auth_user_request, request, conn, type);
}

static auth_user_request_t *
authTryGetUser (auth_user_request_t **auth_user_request, ConnStateData * conn)
{
    if (*auth_user_request)
	return *auth_user_request;
    else if (conn)
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
 */
auth_acl_t
AuthUserRequest::authenticate(auth_user_request_t ** auth_user_request, http_hdr_type headertype, request_t * request, ConnStateData * conn, struct in_addr src_addr)
{
    const char *proxy_auth;
    assert(headertype != 0);

    proxy_auth = httpHeaderGetStr(&request->header, headertype);

    /*
     * a note on proxy_auth logix here:
     * proxy_auth==NULL -> unauthenticated request || already
     * authenticated connection so we test for an authenticated
     * connection when we recieve no authentication header.
     */
    if (((proxy_auth == NULL) && (!authenticateUserAuthenticated(authTryGetUser(auth_user_request,conn))))
	|| (conn && conn->auth_type == AUTH_BROKEN)) {
	/* no header or authentication failed/got corrupted - restart */
	debug(28, 4) ("authenticateAuthenticate: broken auth or no proxy_auth header. Requesting auth header.\n");
	/* something wrong with the AUTH credentials. Force a new attempt */
	if (conn) {
	    conn->auth_type = AUTH_UNKNOWN;
	    if (conn->auth_user_request)
		conn->auth_user_request->unlock();
	    conn->auth_user_request = NULL;
	}
	if (*auth_user_request) {
	    /* unlock the ACL lock */
	    (*auth_user_request)->unlock();
	    auth_user_request = NULL;
	}
	return AUTH_ACL_CHALLENGE;
    }
    /* 
     * Is this an already authenticated connection with a new auth header?
     * No check for function required in the if: its compulsory for conn based 
     * auth modules
     */
    if (proxy_auth && conn && conn->auth_user_request &&
	authenticateUserAuthenticated(conn->auth_user_request) &&
	strcmp(proxy_auth, authscheme_list[conn->auth_user_request->auth_user->auth_module - 1].authConnLastHeader(conn->auth_user_request))) {
	debug(28, 2) ("authenticateAuthenticate: DUPLICATE AUTH - authentication header on already authenticated connection!. AU %p, Current user '%s' proxy_auth %s\n", conn->auth_user_request, conn->auth_user_request->username(), proxy_auth);
	/* remove this request struct - the link is already authed and it can't be to 
	 * reauth.
	 */

	/* This should _only_ ever occur on the first pass through 
	 * authenticateAuthenticate 
	 */
	assert(*auth_user_request == NULL);
	/* unlock the conn lock on the auth_user_request */
	conn->auth_user_request->unlock();
	/* mark the conn as non-authed. */
	conn->auth_user_request = NULL;
	/* Set the connection auth type */
	conn->auth_type = AUTH_UNKNOWN;
    }
    /* we have a proxy auth header and as far as we know this connection has
     * not had bungled connection oriented authentication happen on it. */
    debug(28, 9) ("authenticateAuthenticate: header %s.\n", proxy_auth);
    if (*auth_user_request == NULL) {
	debug(28, 9) ("authenticateAuthenticate: This is a new checklist test on FD:%d\n",
	    conn ? conn->fd : -1);
	if ((!request->auth_user_request)
	    && (!conn || conn->auth_type == AUTH_UNKNOWN)) {
	    /* beginning of a new request check */
	    debug(28, 4) ("authenticateAuthenticate: no connection authentication type\n");
	    if (!authenticateValidateUser(*auth_user_request =
		    createAuthUser(proxy_auth))) {
		/* the decode might have left a username for logging, or a message to
		 * the user */
		if ((*auth_user_request)->username()) {
		    /* lock the user for the request structure link */
		    (*auth_user_request)->lock();
		    request->auth_user_request = *auth_user_request;
		}
		/* unlock the ACL reference granted by ...createAuthUser. */
		(*auth_user_request)->unlock();
		*auth_user_request = NULL;
		return AUTH_ACL_CHALLENGE;
	    }
	    /* the user_request comes prelocked for the caller to createAuthUser (us) */
	} else if (request->auth_user_request) {
	    *auth_user_request = request->auth_user_request;
	    /* lock the user request for this ACL processing */
	    (*auth_user_request)->lock();
	} else {
	    assert (conn);
	    if (conn->auth_user_request != NULL) {
		*auth_user_request = conn->auth_user_request;
		/* lock the user request for this ACL processing */
		(*auth_user_request)->lock();
	    } else {
		/* failed connection based authentication */
		debug(28, 4) ("authenticateAuthenticate: Auth user request %p conn-auth user request %p conn type %d authentication failed.\n",
		    *auth_user_request, conn->auth_user_request, conn->auth_type);
		(*auth_user_request)->unlock();
		*auth_user_request = NULL;
		return AUTH_ACL_CHALLENGE;
	    }
	}
    }
    if (!authenticateUserAuthenticated(*auth_user_request)) {
	/* User not logged in. Log them in */
	authenticateAuthenticateUser(*auth_user_request, request,
	    conn, headertype);
	switch (authenticateDirection(*auth_user_request)) {
	case 1:
	case -2:
	    /* this ACL check is finished. Unlock. */
	    (*auth_user_request)->unlock();
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
		    /* lock the user for the request structure link */
		    (*auth_user_request)->lock();
		    request->auth_user_request = *auth_user_request;
		}
	    }
	    /* this ACL check is finished. Unlock. */
	    (*auth_user_request)->unlock();
	    *auth_user_request = NULL;
	    return AUTH_ACL_CHALLENGE;
	}
    }
    /* copy username to request for logging on client-side */
    /* the credentials are correct at this point */
    if (!request->auth_user_request) {
	/* lock the user for the request structure link */
	(*auth_user_request)->lock();
	request->auth_user_request = *auth_user_request;
	authenticateAuthUserRequestSetIp(*auth_user_request, src_addr);
    }
    /* Unlock the request - we've authenticated it */
    (*auth_user_request)->unlock();
    return AUTH_AUTHENTICATED;
}

auth_acl_t
AuthUserRequest::tryToAuthenticateAndSetAuthUser(auth_user_request_t ** auth_user_request, http_hdr_type headertype, request_t * request, ConnStateData * conn, struct in_addr src_addr)
{
    /* If we have already been called, return the cached value */
    auth_user_request_t *t = authTryGetUser (auth_user_request, conn);
    if (t && t->lastReply != AUTH_ACL_CANNOT_AUTHENTICATE
	&& t->lastReply != AUTH_ACL_HELPER) {
	if (!*auth_user_request)
	    *auth_user_request = t;
	return t->lastReply;
    }
    /* ok, call the actual authenticator routine. */
    auth_acl_t result = authenticate(auth_user_request, headertype, request, conn, src_addr);
    t = authTryGetUser (auth_user_request, conn);
    if (t && result != AUTH_ACL_CANNOT_AUTHENTICATE &&
	result != AUTH_ACL_HELPER)
	t->lastReply = result;
    return result;
}

auth_acl_t
authenticateTryToAuthenticateAndSetAuthUser(auth_user_request_t ** auth_user_request, http_hdr_type headertype, request_t * request, ConnStateData * conn, struct in_addr src_addr)
{
    return AuthUserRequest::tryToAuthenticateAndSetAuthUser (auth_user_request, headertype,request, conn, src_addr);
}

/* authenticateUserRequestUsername: return a pointer to the username in the */
char const *
authenticateUserRequestUsername(auth_user_request_t * auth_user_request)
{
    assert(auth_user_request != NULL);
    return auth_user_request->username();
}

/* returns
 * 0: no output needed
 * 1: send to client
 * -1: send to helper
 * -2: authenticate broken in some fashion
 */
int
authenticateDirection(auth_user_request_t * auth_user_request)
{
    if (!auth_user_request)
	return -2;
    if (authenticateUserAuthenticated(auth_user_request))
	return 0;
    if (auth_user_request->auth_user->auth_module > 0)
	return authscheme_list[auth_user_request->auth_user->auth_module - 1].getdirection(auth_user_request);
    return -2;
}

int
authenticateActiveSchemeCount(void)
{
    int i = 0, rv = 0;
    for (i = 0; authscheme_list && authscheme_list[i].typestr; i++)
	if (authscheme_list[i].configured())
	    rv++;
    debug(29, 9) ("authenticateActiveSchemeCount: %d active.\n", rv);
    return rv;
}

int
authenticateSchemeCount(void)
{
    int i = 0, rv = 0;
    for (i = 0; authscheme_list && authscheme_list[i].typestr; i++)
	rv++;
    debug(29, 9) ("authenticateSchemeCount: %d active.\n", rv);
    return rv;
}

void
authenticateSchemeInit(void)
{
    authSchemeSetup();
}

void
authenticateInit(authConfig * config)
{
    int i;
    authScheme *scheme;
    for (i = 0; i < config->n_configured; i++) {
	scheme = config->schemes + i;
	if (authscheme_list[scheme->Id].init && authscheme_list[scheme->Id].configured()) {
	    authscheme_list[scheme->Id].init(scheme);
	}
    }
    if (!proxy_auth_username_cache)
	AuthUser::cacheInit();
}

void
authenticateShutdown(void)
{
    int i;
    debug(29, 2) ("authenticateShutdown: shutting down auth schemes\n");
    /* free the cache if we are shutting down */
    if (shutting_down)
	hashFreeItems(proxy_auth_username_cache, AuthUserHashPointer::removeFromCache);

    /* find the currently known authscheme types */
    for (i = 0; authscheme_list && authscheme_list[i].typestr; i++) {
	if (authscheme_list[i].donefunc != NULL)
	    authscheme_list[i].donefunc();
	else
	    debug(29, 2) ("authenticateShutdown: scheme %s has not registered a shutdown function.\n", authscheme_list[i].typestr);
	if (shutting_down)
	    authscheme_list[i].typestr = NULL;
    }
}

void
AuthUserRequest::addReplyAuthHeader(HttpReply * rep, auth_user_request_t * auth_user_request, request_t * request, int accelerated, int internal)
/* send the auth types we are configured to support (and have compiled in!) */
{
    http_hdr_type type;
    switch (rep->sline.status) {
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
    debug(29, 9) ("authenticateFixHeader: headertype:%d authuser:%p\n", type, auth_user_request);
    if (((rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
	    || (rep->sline.status == HTTP_UNAUTHORIZED)) && internal)
	/* this is a authenticate-needed response */
    {
	if ((auth_user_request != NULL) && (auth_user_request->auth_user->auth_module > 0) & !authenticateUserAuthenticated(auth_user_request))
	    authscheme_list[auth_user_request->auth_user->auth_module - 1].authFixHeader(auth_user_request, rep, type, request);
	else {
	    int i;
	    authScheme *scheme;
	    /* call each configured & running authscheme */
	    for (i = 0; i < Config.authConfiguration.n_configured; i++) {
		scheme = Config.authConfiguration.schemes + i;
		if (authscheme_list[scheme->Id].Active())
		    authscheme_list[scheme->Id].authFixHeader(NULL, rep, type,
			request);
		else
		    debug(29, 4) ("authenticateFixHeader: Configured scheme %s not Active\n", scheme->typestr);
	    }
	}
    }
    /* 
     * allow protocol specific headers to be _added_ to the existing
     * response - ie digest auth
     */
    if ((auth_user_request != NULL) && (auth_user_request->auth_user->auth_module > 0)
	&& (authscheme_list[auth_user_request->auth_user->auth_module - 1].AddHeader))
	authscheme_list[auth_user_request->auth_user->auth_module - 1].AddHeader(auth_user_request, rep, accelerated);
    if (auth_user_request != NULL)
	auth_user_request->lastReply = AUTH_ACL_CANNOT_AUTHENTICATE;
}

void
authenticateFixHeader(HttpReply * rep, auth_user_request_t * auth_user_request, request_t * request, int accelerated, int internal)
{
    AuthUserRequest::addReplyAuthHeader(rep, auth_user_request, request, accelerated, internal);
}
  

/* call the active auth module and allow it to add a trailer to the request */
void
authenticateAddTrailer(HttpReply * rep, auth_user_request_t * auth_user_request, request_t * request, int accelerated)
{
    if ((auth_user_request != NULL) && (auth_user_request->auth_user->auth_module > 0)
	&& (authscheme_list[auth_user_request->auth_user->auth_module - 1].AddTrailer))
	authscheme_list[auth_user_request->auth_user->auth_module - 1].AddTrailer(auth_user_request, rep, accelerated);
}

void
authenticateAuthUserLock(auth_user_t * auth_user)
{
    debug(29, 9) ("authenticateAuthUserLock auth_user '%p'.\n", auth_user);
    assert(auth_user != NULL);
    auth_user->references++;
    debug(29, 9) ("authenticateAuthUserLock auth_user '%p' now at '%ld'.\n", auth_user, (long int) auth_user->references);
}

void
authenticateAuthUserUnlock(auth_user_t * auth_user)
{
    debug(29, 9) ("authenticateAuthUserUnlock auth_user '%p'.\n", auth_user);
    assert(auth_user != NULL);
    if (auth_user->references > 0) {
	auth_user->references--;
    } else {
	debug(29, 1) ("Attempt to lower Auth User %p refcount below 0!\n", auth_user);
    }
    debug(29, 9) ("authenticateAuthUserUnlock auth_user '%p' now at '%ld'.\n", auth_user, (long int) auth_user->references);
    if (auth_user->references == 0)
	delete auth_user;
}

void
AuthUserRequest::lock()
{
    debug(29, 9) ("AuthUserRequest::lock: auth_user request '%p'.\n", this);
    assert(this != NULL);
    ++references;
    debug(29, 9) ("AuthUserRequest::lock: auth_user request '%p' now at '%ld'.\n", this, (long int) references);
}

void
AuthUserRequest::unlock()
{
    debug(29, 9) ("AuthUserRequest::unlock: auth_user request '%p'.\n", this);
    assert(this != NULL);
    if (references > 0) {
	--references;
    } else {
	debug(29, 1) ("Attempt to lower Auth User request %p refcount below 0!\n", this);
    }
    debug(29, 9) ("AuthUserRequest::unlock: auth_user_request '%p' now at '%ld'.\n", this, (long int) references);
    if (references == 0)
	/* not locked anymore */
	delete this;
}

void
authenticateAuthUserRequestLock(auth_user_request_t * auth_user_request)
{
    auth_user_request->lock();
}

void
authenticateAuthUserRequestUnlock(auth_user_request_t * auth_user_request)
{
    auth_user_request->unlock();
}
  

int
authenticateAuthUserInuse(auth_user_t * auth_user)
/* returns 0 for not in use */
{
    assert(auth_user != NULL);
    return auth_user->references;
}

/* Combine two user structs. ONLY to be called from within a scheme
 * module. The scheme module is responsible for ensuring that the
 * two users _can_ be merged without invalidating all the request
 * scheme data. The scheme is also responsible for merging any user
 * related scheme data itself.
 */
void
AuthUser::absorb (AuthUser *from)
{
    auth_user_request_t *auth_user_request;
    /*
     * XXX combine two authuser structs. Incomplete: it should merge
     * in hash references too and ask the module to merge in scheme
     * data
     */
    debug(29, 5) ("authenticateAuthUserMerge auth_user '%p' into auth_user '%p'.\n", from, this);
    dlink_node *link = from->requests.head;
    while (link) {
	auth_user_request = static_cast<auth_user_request_t *>(link->data);
	dlink_node *tmplink = link;
	link = link->next;
	dlinkDelete(tmplink, &from->requests);
	dlinkAddTail(auth_user_request, tmplink, &requests);
	auth_user_request->auth_user = this;
    }
    references += from->references;
    from->references = 0;
    delete from;
}

void
authenticateAuthUserMerge(auth_user_t * from, auth_user_t * to)
{   
    to->absorb (from);
}

void
AuthUser::operator delete (void *address)
{
    memPoolFree(pool, address);
}

AuthUser::~AuthUser()
{
    auth_user_request_t *auth_user_request;
    dlink_node *link, *tmplink;
    debug(29, 5) ("AuthUser::~AuthUser: Freeing auth_user '%p' with refcount '%ld'.\n", this, (long int) references);
    assert(references == 0);
    /* were they linked in by username ? */
    if (usernamehash) {
	assert(usernamehash->user() == this);
	debug(29, 5) ("AuthUser::~AuthUser: removing usernamehash entry '%p'\n", usernamehash);
	hash_remove_link(proxy_auth_username_cache,
	    (hash_link *) usernamehash);
	/* don't free the key as we use the same user string as the auth_user 
	 * structure */
	delete usernamehash;
    }
    /* remove any outstanding requests */
    link = requests.head;
    while (link) {
	debug(29, 5) ("AuthUser::~AuthUser: removing request entry '%p'\n", link->data);
	auth_user_request = static_cast<auth_user_request_t *>(link->data);
	tmplink = link;
	link = link->next;
	dlinkDelete(tmplink, &requests);
	dlinkNodeDelete(tmplink);
	delete auth_user_request;
    }
    /* free cached acl results */
    aclCacheMatchFlush(&proxy_match_cache);
    /* free seen ip address's */
    authenticateAuthUserClearIp(this);
    if (scheme_data && auth_module > 0)
	authscheme_list[auth_module - 1].FreeUser(this);
    /* prevent accidental reuse */
    auth_type = AUTH_UNKNOWN;
}

void
AuthUser::cacheInit(void)
{
    if (!proxy_auth_username_cache) {
	/* First time around, 7921 should be big enough */
	proxy_auth_username_cache =
	    hash_create((HASHCMP *) strcmp, 7921, hash_string);
	assert(proxy_auth_username_cache);
	eventAdd("User Cache Maintenance", cacheCleanup, NULL, Config.authenticateGCInterval, 1);
    }
}

void
AuthUser::cacheCleanup(void *datanotused)
{
    /*
     * We walk the hash by username as that is the unique key we use.
     * For big hashs we could consider stepping through the cache, 100/200
     * entries at a time. Lets see how it flys first.
     */
    AuthUserHashPointer *usernamehash;
    auth_user_t *auth_user;
    char const *username = NULL;
    debug(29, 3) ("AuthUser::cacheCleanup: Cleaning the user cache now\n");
    debug(29, 3) ("AuthUser::cacheCleanup: Current time: %ld\n", (long int) current_time.tv_sec);
    hash_first(proxy_auth_username_cache);
    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
	auth_user = usernamehash->user();
	username = auth_user->username();

	/* if we need to have inpedendent expiry clauses, insert a module call
	 * here */
	debug(29, 4) ("AuthUser::cacheCleanup: Cache entry:\n\tType: %d\n\tUsername: %s\n\texpires: %ld\n\treferences: %ld\n", auth_user->auth_type, username, (long int) (auth_user->expiretime + Config.authenticateTTL), (long int) auth_user->references);
	if (auth_user->expiretime + Config.authenticateTTL <= current_time.tv_sec) {
	    debug(29, 5) ("AuthUser::cacheCleanup: Removing user %s from cache due to timeout.\n", username);
	    /* the minus 1 accounts for the cache lock */
	    if (!(authenticateAuthUserInuse(auth_user) - 1))
		/* we don't warn if we leave the user in the cache, 
		 * because other modules (ie delay pools) may keep
		 * locks on users, and thats legitimate
		 */
		authenticateAuthUserUnlock(auth_user);
	}
    }
    debug(29, 3) ("AuthUser::cacheCleanup: Finished cleaning the user cache.\n");
    eventAdd("User Cache Maintenance", cacheCleanup, NULL, Config.authenticateGCInterval, 1);
}

/*
 * authenticateUserCacheRestart() cleans all config-dependent data from the 
 * auth_user cache. It DOES NOT Flush the user cache.
 */

void
authenticateUserCacheRestart(void)
{
    AuthUserHashPointer *usernamehash;
    auth_user_t *auth_user;
    debug(29, 3) ("authenticateUserCacheRestart: Clearing config dependent cache data.\n");
    hash_first(proxy_auth_username_cache);
    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
	auth_user = usernamehash->user();
	debug(29, 5) ("authenticateUserCacheRestat: Clearing cache ACL results for user: %s\n", auth_user->username());
    }

}

/*
 * called to add another auth scheme module
 */
void
authSchemeAdd(const char *type, AUTHSSETUP * setup)
{
    int i;
    debug(29, 4) ("authSchemeAdd: adding %s\n", type);
    /* find the number of currently known authscheme types */
    for (i = 0; authscheme_list && authscheme_list[i].typestr; i++) {
	assert(strcmp(authscheme_list[i].typestr, type) != 0);
    }
    /* add the new type */
    authscheme_list = static_cast<authscheme_entry_t *>(xrealloc(authscheme_list, (i + 2) * sizeof(authscheme_entry_t)));
    memset(&authscheme_list[i], 0, sizeof(authscheme_entry_t));
    memset(&authscheme_list[i + 1], 0, sizeof(authscheme_entry_t));
    authscheme_list[i].typestr = type;
    /* Call the scheme module to set up capabilities and initialize any global data */
    setup(&authscheme_list[i]);
}

/* _auth_user_hash_pointe */

void
AuthUserHashPointer::removeFromCache(void *usernamehash_p)
{
    AuthUserHashPointer *usernamehash = static_cast<AuthUserHashPointer *>(usernamehash_p);
    auth_user_t *auth_user = usernamehash->auth_user;
    if ((authenticateAuthUserInuse(auth_user) - 1))
	debug(29, 1) ("AuthUserHashPointer::removeFromCache: entry in use - not freeing\n");
    authenticateAuthUserUnlock(auth_user);
    /* TODO: change behaviour - we remove from the auth user list here, and then unlock, and the
     * delete ourselves.
     */
}

void *
AuthUserHashPointer::operator new (size_t byteCount)
{
    assert (byteCount == sizeof (AuthUserHashPointer));
    if (!pool)
	pool = memPoolCreate("Auth user hash link", sizeof(AuthUserHashPointer));
    return static_cast<AuthUserHashPointer *>(memPoolAlloc(pool));
}

void
AuthUserHashPointer::operator delete (void *address)
{
    memPoolFree(pool, address);
}

AuthUserHashPointer::AuthUserHashPointer (auth_user_t * anAuth_user):
auth_user (anAuth_user)
{
    key = (void *)anAuth_user->username();
    next = NULL;
    hash_join(proxy_auth_username_cache, (hash_link *) this);
    /* lock for presence in the cache */
    authenticateAuthUserLock(auth_user);
}

AuthUser *
AuthUserHashPointer::user() const
{
    return auth_user;
}

/* C bindings */
/* UserNameCacheAdd: add a auth_user structure to the username cache */
void
authenticateUserNameCacheAdd(auth_user_t * auth_user)
{
    auth_user->usernamehash = new AuthUserHashPointer (auth_user);
}

auth_user_t*
authUserHashPointerUser (auth_user_hash_pointer *aHashEntry)
{
    return aHashEntry->user();
}

