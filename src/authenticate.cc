
/*
 * $Id: authenticate.cc,v 1.22 2001/03/10 00:55:36 hno Exp $
 *
 * DEBUG: section 29    Authenticator
 * AUTHOR: Duane Wessels
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

static void
     authenticateDecodeAuth(const char *proxy_auth, auth_user_request_t * auth_user_request);

/*
 *
 * Private Data
 *
 */

MemPool *auth_user_request_pool = NULL;

/* Generic Functions */


static int
authenticateAuthSchemeConfigured(const char *proxy_auth)
{
    authScheme *scheme;
    int i;
    for (i = 0; i < Config.authConfig.n_configured; i++) {
	scheme = Config.authConfig.schemes + i;
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
authenticateDecodeAuth(const char *proxy_auth, auth_user_request_t * auth_user_request)
{
    int i = 0;
    assert(proxy_auth != NULL);
    assert(auth_user_request != NULL);	/* we need this created for us. */
    debug(29, 9) ("authenticateDecodeAuth: header = '%s'\n", proxy_auth);
    if (authenticateAuthSchemeConfigured(proxy_auth)) {
	/* we're configured to use this scheme - but is it active ? */
	if ((i = authenticateAuthSchemeId(proxy_auth)) != -1) {
	    authscheme_list[i].decodeauth(auth_user_request, proxy_auth);
	    auth_user_request->auth_user->auth_module = i + 1;
	    return;
	}
    }
    debug(29, 1)
	("authenticateDecodeAuth: Unsupported or unconfigured proxy-auth scheme, '%s'\n",
	proxy_auth);
    return;
}

/* clear any connection related authentication details */
void
authenticateOnCloseConnection(ConnStateData * conn)
{
    auth_user_request_t *auth_user_request;
    assert(conn != NULL);
    if (conn->auth_user_request != NULL) {
	auth_user_request = conn->auth_user_request;
	if (authscheme_list[auth_user_request->auth_user->auth_module - 1].oncloseconnection) {
	    authscheme_list[auth_user_request->auth_user->auth_module - 1].oncloseconnection(conn);
	}
    }
}

/**** PUBLIC FUNCTIONS (ALL GENERIC!)  ****/

/* send the initial data to an authenticator module */
void
authenticateStart(auth_user_request_t * auth_user_request, RH * handler, void *data)
{
    assert(auth_user_request);
    assert(handler);
    debug(29, 9) ("authenticateStart: auth_user_request '%p'\n", auth_user_request);
    if (auth_user_request->auth_user->auth_module > 0)
	authscheme_list[auth_user_request->auth_user->auth_module - 1].authStart(auth_user_request, handler, data);
    else
	handler(data, NULL);
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
    /* any other sanity checks that we need in the future */

    /* Thus should a module call to something like authValidate */

    /* finally return ok */
    debug(29, 4) ("authenticateValidateUser: Validated Auth_user request '%p'.\n", auth_user_request);
    return 1;

}

auth_user_t *
authenticateAuthUserNew(const char *scheme)
{
    auth_user_t *temp_auth;
    temp_auth = memAllocate(MEM_AUTH_USER_T);
    assert(temp_auth != NULL);
    temp_auth->auth_type = AUTH_UNKNOWN;
    temp_auth->references = 0;
    temp_auth->auth_module = authenticateAuthSchemeId(scheme) + 1;
    temp_auth->usernamehash = NULL;
    return temp_auth;
}

static auth_user_request_t *
authenticateAuthUserRequestNew(void)
{
    auth_user_request_t *temp_request;
    if (!auth_user_request_pool)
	auth_user_request_pool = memPoolCreate("Authenticate Request Data", sizeof(auth_user_request_t));
    temp_request = memPoolAlloc(auth_user_request_pool);
    assert(temp_request != NULL);
    temp_request->auth_user = NULL;
    temp_request->message = NULL;
    temp_request->scheme_data = NULL;
    temp_request->references = 0;
    return temp_request;
}

static void
authenticateAuthUserRequestFree(auth_user_request_t * auth_user_request)
{
    dlink_node *link;
    debug(29, 5) ("authenticateAuthUserRequestFree: freeing request %p\n", auth_user_request);
    if (!auth_user_request)
	return;
    assert(auth_user_request->references == 0);
    if (auth_user_request->auth_user) {
	if (auth_user_request->scheme_data != NULL) {
	    /* we MUST know the module */
	    assert((auth_user_request->auth_user->auth_module > 0));
	    /* and the module MUST support requestFree if it has created scheme data */
	    assert(authscheme_list[auth_user_request->auth_user->auth_module - 1].requestFree != NULL);
	    authscheme_list[auth_user_request->auth_user->auth_module - 1].requestFree(auth_user_request);
	}
	/* unlink from the auth_user struct */
	link = auth_user_request->auth_user->requests.head;
	while (link && (link->data != auth_user_request))
	    link = link->next;
	assert(link != NULL);
	dlinkDelete(link, &auth_user_request->auth_user->requests);
	dlinkNodeDelete(link);

	/* unlock the request structure's lock */
	authenticateAuthUserUnlock(auth_user_request->auth_user);
	auth_user_request->auth_user = NULL;
    } else
	assert(auth_user_request->scheme_data == NULL);
    if (auth_user_request->message)
	xfree(auth_user_request->message);
}

char *
authenticateAuthUserRequestMessage(auth_user_request_t * auth_user_request)
{
    if (auth_user_request)
	return auth_user_request->message;
    return NULL;
}

void
authenticateAuthUserRequestSetIp(auth_user_request_t * auth_user_request, struct in_addr ipaddr)
{
    if (auth_user_request->auth_user)
	if (!auth_user_request->auth_user->ipaddr.s_addr)
	    auth_user_request->auth_user->ipaddr = ipaddr;
}

/* Get Auth User: Return a filled out auth_user structure for the given
 * Proxy Auth (or Auth) header. It may be a cached Auth User or a new
 * Unauthenticated structure. The structure is given an inital lock here.
 */
auth_user_request_t *
authenticateGetAuthUser(const char *proxy_auth)
{
    auth_user_request_t *auth_user_request = authenticateAuthUserRequestNew();
    /* and lock for the callers instance */
    authenticateAuthUserRequestLock(auth_user_request);
    authenticateDecodeAuth(proxy_auth, auth_user_request);
    return auth_user_request;
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
 * authenticateAuthenticateUser: log this user request in.
 * Cache hits may change the auth_user pointer in the structure if needed.
 * This is basically a handle approach.
 */
void
authenticateAuthenticateUser(auth_user_request_t * auth_user_request, request_t * request, ConnStateData * conn, http_hdr_type type)
{
    assert(auth_user_request != NULL);
    if (auth_user_request->auth_user->auth_module > 0)
	authscheme_list[auth_user_request->auth_user->auth_module - 1].authAuthenticate(auth_user_request, request, conn, type);
}

/* authenticateUserUsername: return a pointer to the username in the */
char *
authenticateUserUsername(auth_user_t * auth_user)
{
    if (!auth_user)
	return NULL;
    if (auth_user->auth_module > 0)
	return authscheme_list[auth_user->auth_module - 1].authUserUsername(auth_user);
    return NULL;
}

/* authenticateUserRequestUsername: return a pointer to the username in the */
char *
authenticateUserRequestUsername(auth_user_request_t * auth_user_request)
{
    assert(auth_user_request != NULL);
    if (auth_user_request->auth_user)
	return authenticateUserUsername(auth_user_request->auth_user);
    else
	return NULL;
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
	authenticateInitUserCache();
}

void
authenticateShutdown(void)
{
    int i;
    debug(29, 2) ("authenticateShutdown: shutting down auth schemes\n");
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
authenticateFixHeader(HttpReply * rep, auth_user_request_t * auth_user_request, request_t * request, int accelerated)
/* send the auth types we are configured to support (and have compiled in!) */
{
/*    auth_type_t auth_type=err->auth_type;
 * auth_state_t auth_state=err->auth_state;
 * char *authchallenge=err->authchallenge;
 * auth_user_request_t *auth_user_request=err->auth_user_request;
 */
    int type = 0;
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
	break;
    }
    debug(29, 9) ("authenticateFixHeader: headertype:%d authuser:%p\n", type, auth_user_request);
    if ((rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
	|| (rep->sline.status == HTTP_UNAUTHORIZED))
	/* this is a authenticate-needed response */
    {
	if ((auth_user_request != NULL) && (auth_user_request->auth_user->auth_module > 0))
	    authscheme_list[auth_user_request->auth_user->auth_module - 1].authFixHeader(auth_user_request, rep, type, request);
	else {
	    int i;
	    authScheme *scheme;
	    /* call each configured & running authscheme */
	    for (i = 0; i < Config.authConfig.n_configured; i++) {
		scheme = Config.authConfig.schemes + i;
		if (authscheme_list[scheme->Id].Active())
		    authscheme_list[scheme->Id].authFixHeader(auth_user_request, rep, type,
			request);
		else
		    debug(29, 4) ("authenticateFixHeader: Configured scheme %s not Active\n", scheme->typestr);
	    }
	}
    }
    if ((auth_user_request != NULL) && (auth_user_request->auth_user->auth_module > 0)
	&& (authscheme_list[auth_user_request->auth_user->auth_module - 1].AddHeader))
	authscheme_list[auth_user_request->auth_user->auth_module - 1].AddHeader(auth_user_request, rep, accelerated);
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
    debug(29, 9) ("authenticateAuthUserLock auth_user '%p' now at '%d'.\n", auth_user, auth_user->references);
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
    debug(29, 9) ("authenticateAuthUserUnlock auth_user '%p' now at '%d'.\n", auth_user, auth_user->references);
    if (auth_user->references == 0)
	authenticateFreeProxyAuthUser(auth_user);
}

void
authenticateAuthUserRequestLock(auth_user_request_t * auth_user_request)
{
    debug(29, 9) ("authenticateAuthUserRequestLock auth_user request '%p'.\n", auth_user_request);
    assert(auth_user_request != NULL);
    auth_user_request->references++;
    debug(29, 9) ("authenticateAuthUserRequestLock auth_user request '%p' now at '%d'.\n", auth_user_request, auth_user_request->references);
}

void
authenticateAuthUserRequestUnlock(auth_user_request_t * auth_user_request)
{
    debug(29, 9) ("authenticateAuthUserRequestUnlock auth_user request '%p'.\n", auth_user_request);
    assert(auth_user_request != NULL);
    if (auth_user_request->references > 0) {
	auth_user_request->references--;
    } else {
	debug(29, 1) ("Attempt to lower Auth User request %p refcount below 0!\n", auth_user_request);
    }
    debug(29, 9) ("authenticateAuthUserRequestUnlock auth_user_request '%p' now at '%d'.\n", auth_user_request, auth_user_request->references);
    if (auth_user_request->references == 0) {
	/* not locked anymore */
	authenticateAuthUserRequestFree(auth_user_request);
    }
}

int
authenticateAuthUserInuse(auth_user_t * auth_user)
/* returns 0 for not in use */
{
    assert(auth_user != NULL);
    return auth_user->references;
}

/* Combine two user structs. ONLY to be called from within a scheme module.
 * The scheme module is responsible for ensuring that the two users _can_ be merged 
 * without invalidating all the request scheme data. 
 * the scheme is also responsible for merging any user related scheme data itself. */
void
authenticateAuthUserMerge(auth_user_t * from, auth_user_t * to)
{
    dlink_node *link, *tmplink;
    auth_user_request_t *auth_user_request;
/* XXX combine two authuser structs. Incomplete: it should merge in hash references 
 * too and ask the module to merge in scheme data */
    debug(29, 5) ("authenticateAuthUserMerge auth_user '%p' into auth_user '%p'.\n", from, to);
    link = from->requests.head;
    while (link) {
	auth_user_request = link->data;
	tmplink = link;
	link = link->next;
	dlinkDelete(tmplink, &from->requests);
	dlinkAddTail(auth_user_request, tmplink, &to->requests);
	auth_user_request->auth_user = to;
    }
    to->references += from->references;
    from->references = 0;
    authenticateFreeProxyAuthUser(from);
}

void
authenticateFreeProxyAuthUser(void *data)
{
    auth_user_t *u = data;
    auth_user_request_t *auth_user_request;
    dlink_node *link, *tmplink;
    assert(data != NULL);
    debug(29, 5) ("authenticateFreeProxyAuthUser: Freeing auth_user '%p' with refcount '%d'.\n", u, u->references);
    assert(u->references == 0);
    /* were they linked in by username ? */
    if (u->usernamehash) {
	assert(u->usernamehash->auth_user == u);
	debug(29, 5) ("authenticateFreeProxyAuthUser: removing usernamehash entry '%p'\n", u->usernamehash);
	hash_remove_link(proxy_auth_username_cache,
	    (hash_link *) u->usernamehash);
	/* don't free the key as we use the same user string as the auth_user 
	 * structure */
	memFree(u->usernamehash, MEM_AUTH_USER_HASH);
    }
    /* remove any outstanding requests */
    link = u->requests.head;
    while (link) {
	debug(29, 5) ("authenticateFreeProxyAuthUser: removing request entry '%p'\n", link->data);
	auth_user_request = link->data;
	tmplink = link;
	link = link->next;
	dlinkDelete(tmplink, &u->requests);
	dlinkNodeDelete(tmplink);
	authenticateAuthUserRequestFree(auth_user_request);
    }
    /* free cached acl results */
    aclCacheMatchFlush(&u->proxy_match_cache);
    if (u->scheme_data && u->auth_module > 0)
	authscheme_list[u->auth_module - 1].FreeUser(u);
    /* prevent accidental reuse */
    u->auth_type = AUTH_UNKNOWN;
    memFree(u, MEM_AUTH_USER_T);
}

void
authenticateInitUserCache(void)
{
    if (!proxy_auth_username_cache) {
	/* First time around, 7921 should be big enough */
	proxy_auth_username_cache =
	    hash_create((HASHCMP *) strcmp, 7921, hash_string);
	assert(proxy_auth_username_cache);
	eventAdd("User Cache Maintenance", authenticateProxyUserCacheCleanup, NULL, Config.authenticateGCInterval, 1);
    }
}

void
authenticateProxyUserCacheCleanup(void *datanotused)
{
    /*
     * We walk the hash by username as that is the unique key we use.
     * For big hashs we could consider stepping through the cache, 100/200
     * entries at a time. Lets see how it flys first.
     */
    auth_user_hash_pointer *usernamehash;
    auth_user_t *auth_user;
    char *username = NULL;
    debug(29, 3) ("authenticateProxyUserCacheCleanup: Cleaning the user cache now\n");
    debug(29, 3) ("authenticateProxyUserCacheCleanup: Current time: %d\n", current_time.tv_sec);
    hash_first(proxy_auth_username_cache);
    while ((usernamehash = ((auth_user_hash_pointer *) hash_next(proxy_auth_username_cache)))) {
	auth_user = usernamehash->auth_user;
	username = authenticateUserUsername(auth_user);

	/* if we need to have inpedendent expiry clauses, insert a module call
	 * here */
	debug(29, 4) ("authenticateProxyUserCacheCleanup: Cache entry:\n\tType: %d\n\tUsername: %s\n\texpires: %d\n\treferences: %d\n", auth_user->auth_type, username, auth_user->expiretime + Config.authenticateTTL, auth_user->references);
	if (auth_user->expiretime + Config.authenticateTTL <= current_time.tv_sec) {
	    debug(29, 5) ("authenticateProxyUserCacheCleanup: Removing user %s from cache due to timeout.\n", username);
	    /* the minus 1 accounts for the cache lock */
	    if ((authenticateAuthUserInuse(auth_user) - 1))
		debug(29, 4) ("authenticateProxyUserCacheCleanup: this cache entry has expired AND has a non-zero ref count.\n");
	    else
		authenticateAuthUserUnlock(auth_user);
	}
    }
    debug(29, 3) ("authenticateProxyUserCacheCleanup: Finished cleaning the user cache.\n");
    eventAdd("User Cache Maintenance", authenticateProxyUserCacheCleanup, NULL, Config.authenticateGCInterval, 1);
}

/*
 * authenticateUserCacheRestart() cleans all config-dependent data from the 
 * auth_user cache. It DOES NOT Flush the user cache.
 */

void
authenticateUserCacheRestart(void)
{
    auth_user_hash_pointer *usernamehash;
    auth_user_t *auth_user;
    char *username = NULL;
    debug(29, 3) ("authenticateUserCacheRestart: Clearing config dependent cache data.\n");
    hash_first(proxy_auth_username_cache);
    while ((usernamehash = ((auth_user_hash_pointer *) hash_next(proxy_auth_username_cache)))) {
	auth_user = usernamehash->auth_user;
	username = authenticateUserUsername(auth_user);
	debug(29, 5) ("authenticateUserCacheRestat: Clearing cache ACL results for user: %s\n", username);
	aclCacheMatchFlush(&auth_user->proxy_match_cache);
    }

}

/*
 * called to add another auth scheme module
 */
void
authSchemeAdd(char *type, AUTHSSETUP * setup)
{
    int i;
    debug(29, 4) ("authSchemeAdd: adding %s", type);
    /* find the number of currently known authscheme types */
    for (i = 0; authscheme_list && authscheme_list[i].typestr; i++) {
	assert(strcmp(authscheme_list[i].typestr, type) != 0);
    }
    /* add the new type */
    authscheme_list = xrealloc(authscheme_list, (i + 2) * sizeof(authscheme_entry_t));
    memset(&authscheme_list[i + 1], 0, sizeof(authscheme_entry_t));
    authscheme_list[i].typestr = type;
    /* Call the scheme module to set up capabilities and initialize any global data */
    setup(&authscheme_list[i]);
}



/* UserNameCacheAdd: add a auth_user structure to the username cache */
void
authenticateUserNameCacheAdd(auth_user_t * auth_user)
{
    auth_user_hash_pointer *usernamehash;
    usernamehash = memAllocate(MEM_AUTH_USER_HASH);
    usernamehash->key = authenticateUserUsername(auth_user);
    usernamehash->auth_user = auth_user;
    hash_join(proxy_auth_username_cache, (hash_link *) usernamehash);
    auth_user->usernamehash = usernamehash;
    /* lock for presence in the cache */
    authenticateAuthUserLock(auth_user);
}



/*
 * check the user for ip changes timeouts
 * 0 = failed check
 * 1 = ip requirements are ok.
 */
/* TODO:
 * ip_expire data should be in a struct of it's own - for code reuse */
int
authenticateCheckAuthUserIP(struct in_addr request_src_addr, auth_user_request_t * auth_user_request)
{
    char *username = authenticateUserRequestUsername(auth_user_request);
    if (request_src_addr.s_addr == auth_user_request->auth_user->ipaddr.s_addr || auth_user_request->auth_user->ip_expiretime + Config.authenticateIpTTL <= squid_curtime) {
	/* user has not moved ip or had the ip timeout expire */
	if ((auth_user_request->auth_user->auth_type == AUTH_UNKNOWN) ||
	    (auth_user_request->auth_user->auth_type == AUTH_BROKEN)) {
	    debug(29, 1) ("authenticateCheckProxyAuthIP: broken or unknown auth type %d.\n", auth_user_request->auth_user->auth_type);
	    return 0;
	}
	username = authenticateUserRequestUsername(auth_user_request);
	/* Update IP ttl */
	auth_user_request->auth_user->ip_expiretime = squid_curtime;
	auth_user_request->auth_user->ipaddr = request_src_addr;
	return 1;
    } else {
	char *ip1 = xstrdup(inet_ntoa(auth_user_request->auth_user->ipaddr));
	char *ip2 = xstrdup(inet_ntoa(request_src_addr));
	if (Config.onoff.authenticateIpTTLStrict) {
	    debug(29, 1) ("aclMatchProxyAuth: user '%s' tried to use multiple IP addresses! (%s, %s)\n ", username, ip1, ip2);
	} else {
	    /* Non-strict mode. Reassign ownership to the new IP */
	    auth_user_request->auth_user->ipaddr.s_addr = request_src_addr.s_addr;
	    debug(29, 1) ("aclMatchProxyAuth: user '%s' has changed IP address (%s, %s)\n ", username, ip1, ip2);
	}
	safe_free(ip1);
	safe_free(ip2);
	/* and deny access */
	return 0;
    }
}
