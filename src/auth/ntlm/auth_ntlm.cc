
/*
 * $Id: auth_ntlm.cc,v 1.1 2001/01/07 23:36:48 hno Exp $
 *
 * DEBUG: section 29    NTLM Authenticator
 * AUTHOR: Robert Collins
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
#include "auth_ntlm.h"

static void
authenticateStateFree(authenticateStateData * r)
{
    cbdataFree(r);
}

/* NTLM Scheme */
static HLPSCB authenticateNTLMHandleReply;
static HLPSCB authenticateNTLMHandleplaceholder;
static AUTHSACTIVE authenticateNTLMActive;
static AUTHSAUTHED authNTLMAuthenticated;
static AUTHSAUTHUSER authenticateNTLMAuthenticateUser;
static AUTHSFIXERR authenticateNTLMFixErrorHeader;
static AUTHSFREE authenticateNTLMFreeUser;
static AUTHSDIRECTION authenticateNTLMDirection;
static AUTHSDECODE authenticateDecodeNTLMAuth;
static AUTHSDUMP authNTLMCfgDump;
static AUTHSFREECONFIG authNTLMFreeConfig;
static AUTHSINIT authNTLMInit;
static AUTHSONCLOSEC authenticateNTLMOnCloseConnection;
static AUTHSUSERNAME authenticateNTLMUsername;
static AUTHSREQFREE authNTLMAURequestFree;
static AUTHSPARSE authNTLMParse;
static AUTHSSTART authenticateNTLMStart;
static AUTHSSTATS authenticateNTLMStats;
static AUTHSSHUTDOWN authNTLMDone;

/* helper callbacks to handle per server state data */
static HLPSAVAIL authenticateNTLMHelperServerAvailable;
static HLPSONEQ authenticateNTLMHelperServerOnEmpty;

static statefulhelper *ntlmauthenticators = NULL;

CBDATA_TYPE(authenticateStateData);

static int authntlm_initialised = 0;

MemPool *ntlm_helper_state_pool = NULL;
MemPool *ntlm_user_pool = NULL;
MemPool *ntlm_request_pool = NULL;
static auth_ntlm_config *ntlmConfig = NULL;

static hash_table *proxy_auth_cache = NULL;

/*
 *
 * Private Functions
 *
 */

void
authNTLMDone(void)
{
//    memPoolDestroy(ufs_state_pool);

    if (ntlmauthenticators)
	helperStatefulShutdown(ntlmauthenticators);
    authntlm_initialised = 0;
    if (!shutting_down)
	return;
    helperStatefulFree(ntlmauthenticators);
    ntlmauthenticators = NULL;
    memPoolDestroy(ntlm_helper_state_pool);
    memPoolDestroy(ntlm_request_pool);
    memPoolDestroy(ntlm_user_pool);

}

/* free any allocated configuration details */
void
authNTLMFreeConfig(authScheme * scheme)
{
    if (ntlmConfig == NULL)
	return;
    assert(ntlmConfig == scheme->scheme_data);
    if (ntlmConfig->authenticate)
	wordlistDestroy(&ntlmConfig->authenticate);
    xfree(ntlmConfig);
    ntlmConfig = NULL;
}

static void
authNTLMCfgDump(StoreEntry * entry, const char *name, authScheme * scheme)
{
    auth_ntlm_config *config = scheme->scheme_data;
    wordlist *list = config->authenticate;
    storeAppendPrintf(entry, "%s %s", name, "ntlm");
    while (list != NULL) {
	storeAppendPrintf(entry, " %s", list->key);
	list = list->next;
    }
    storeAppendPrintf(entry, "\n%s %s children %d\n%s %s max_challenge_reuses %d\n%s %s max_challenge_lifetime %d seconds\n",
	name, "ntlm", config->authenticateChildren,
	name, "ntlm", config->challengeuses,
	name, "ntlm", config->challengelifetime);

}

static void
authNTLMParse(authScheme * scheme, int n_configured, char *param_str)
{
    if (scheme->scheme_data == NULL) {
	assert(ntlmConfig == NULL);
	/* this is the first param to be found */
	scheme->scheme_data = xmalloc(sizeof(auth_ntlm_config));
	memset(scheme->scheme_data, 0, sizeof(auth_ntlm_config));
	ntlmConfig = scheme->scheme_data;
	ntlmConfig->authenticateChildren = 5;
	ntlmConfig->challengeuses = 0;
	ntlmConfig->challengelifetime = 60;
    }
    ntlmConfig = scheme->scheme_data;
    if (strcasecmp(param_str, "program") == 0) {
	parse_wordlist(&ntlmConfig->authenticate);
	requirePathnameExists("authparam ntlm program", ntlmConfig->authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
	parse_int(&ntlmConfig->authenticateChildren);
    } else if (strcasecmp(param_str, "max_challenge_reuses") == 0) {
	parse_int(&ntlmConfig->challengeuses);
    } else if (strcasecmp(param_str, "max_challenge_lifetime") == 0) {
	parse_time_t(&ntlmConfig->challengelifetime);
    } else {
	debug(28, 0) ("unrecognised ntlm auth scheme parameter '%s'\n", param_str);
    }
}


void
authSchemeSetup_ntlm(authscheme_entry_t * authscheme)
{
#if 0
    static int ntlminit = 0;
#endif
    assert(!authntlm_initialised);
    authscheme->Active = authenticateNTLMActive;
    authscheme->parse = authNTLMParse;
    authscheme->dump = authNTLMCfgDump;
    authscheme->requestFree = authNTLMAURequestFree;
    authscheme->freeconfig = authNTLMFreeConfig;
    authscheme->init = authNTLMInit;
    authscheme->authAuthenticate = authenticateNTLMAuthenticateUser;
    authscheme->authenticated = authNTLMAuthenticated;
    authscheme->authFixHeader = authenticateNTLMFixErrorHeader;
    authscheme->FreeUser = authenticateNTLMFreeUser;
    authscheme->authStart = authenticateNTLMStart;
    authscheme->authStats = authenticateNTLMStats;
    authscheme->authUserUsername = authenticateNTLMUsername;
    authscheme->getdirection = authenticateNTLMDirection;
    authscheme->decodeauth = authenticateDecodeNTLMAuth;
    authscheme->donefunc = authNTLMDone;
    authscheme->oncloseconnection = authenticateNTLMOnCloseConnection;
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
static void
authNTLMInit(authScheme * scheme)
{
    static int ntlminit = 0;
    if (ntlmConfig->authenticate) {
	if (!ntlm_helper_state_pool)
	    ntlm_helper_state_pool = memPoolCreate("NTLM Helper State data", sizeof(ntlm_helper_state_t));
	if (!ntlm_user_pool)
	    ntlm_user_pool = memPoolCreate("NTLM Scheme User Data", sizeof(ntlm_user_t));
	if (!ntlm_request_pool)
	    ntlm_request_pool = memPoolCreate("NTLM Scheme Request Data", sizeof(ntlm_request_t));
	authntlm_initialised = 1;
	if (ntlmauthenticators == NULL)
	    ntlmauthenticators = helperStatefulCreate("ntlmauthenticator");
	if (!proxy_auth_cache)
	    proxy_auth_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
	assert(proxy_auth_cache);
	ntlmauthenticators->cmdline = ntlmConfig->authenticate;
	ntlmauthenticators->n_to_start = ntlmConfig->authenticateChildren;
	ntlmauthenticators->ipc_type = IPC_TCP_SOCKET;
	ntlmauthenticators->datapool = ntlm_helper_state_pool;
	ntlmauthenticators->IsAvailable = authenticateNTLMHelperServerAvailable;
	ntlmauthenticators->OnEmptyQueue = authenticateNTLMHelperServerOnEmpty;
	helperStatefulOpenServers(ntlmauthenticators);
	/* TODO: In here send the initial YR to preinitialise the challenge cache */
	/* Think about this... currently we ask when the challenge is needed. Better? */
	if (!ntlminit) {
	    cachemgrRegister("ntlmauthenticator",
		"User NTLM Authenticator Stats",
		authenticateNTLMStats, 0, 1);
	    ntlminit++;
	}
	CBDATA_INIT_TYPE(authenticateStateData);
    }
}

int
authenticateNTLMActive()
{
    if (authntlm_initialised)
	return 1;
    else
	return 0;
}

/* NTLM Scheme */

int
authenticateNTLMDirection(auth_user_request_t * auth_user_request)
{
    ntlm_request_t *ntlm_request = auth_user_request->scheme_data;
/* null auth_user is checked for by authenticateDirection */
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NONE:	/* no progress at all. */
	debug(28, 1) ("authenticateNTLMDirection: called before NTLM Authenticate!. Report a bug to squid-dev.\n");
	return -2;
    case AUTHENTICATE_STATE_NEGOTIATE:		/* send to helper */
    case AUTHENTICATE_STATE_RESPONSE:	/*send to helper */
	return -1;
    case AUTHENTICATE_STATE_CHALLENGE:		/* send to client */
	return 1;
    case AUTHENTICATE_STATE_DONE:	/* do nothing.. */
	return 0;
    }
    return -2;
}

/*
 * Send the authenticate error header(s). Note: IE has a bug and the NTLM header
 * must be first. To ensure that, the configure use --enable-auth=ntlm, anything
 * else.
 */
void
authenticateNTLMFixErrorHeader(auth_user_request_t * auth_user_request, HttpReply * rep, http_hdr_type type, request_t * request)
{
    ntlm_request_t *ntlm_request;
    if (ntlmConfig->authenticate) {
	/* New request, no user details */
	if (auth_user_request == NULL) {
	    debug(29, 9) ("authenticateNTLMFixErrorHeader: Sending type:%d header: 'NTLM'\n", type);
	    httpHeaderPutStrf(&rep->header, type, "NTLM");
	    /* drop the connection */
	    httpHeaderDelByName(&rep->header, "keep-alive");
	    /* NTLM has problems if the initial connection is not dropped
	     * I haven't checked the RFC compliance of this hack - RBCollins */
	    request->flags.proxy_keepalive = 0;
	} else {
	    ntlm_request = auth_user_request->scheme_data;
	    switch (ntlm_request->auth_state) {
	    case AUTHENTICATE_STATE_NONE:
		debug(29, 9) ("authenticateNTLMFixErrorHeader: Sending type:%d header: 'NTLM'\n", type);
		httpHeaderPutStrf(&rep->header, type, "NTLM");
		/* drop the connection */
		httpHeaderDelByName(&rep->header, "keep-alive");
		/* NTLM has problems if the initial connection is not dropped
		 * I haven't checked the RFC compliance of this hack - RBCollins */
		request->flags.proxy_keepalive = 0;
		break;
	    case AUTHENTICATE_STATE_CHALLENGE:
		/* we are 'waiting' for a response */
		/* pass the challenge to the client */
		debug(29, 9) ("authenticateNTLMFixErrorHeader: Sending type:%d header: 'NTLM %s'\n", type, ntlm_request->authchallenge);
		httpHeaderPutStrf(&rep->header, type, "NTLM %s", ntlm_request->authchallenge);
		break;
	    default:
		debug(29, 0) ("authenticateNTLMFixErrorHeader: state %d.\n", ntlm_request->auth_state);
		fatal("unexpected state in AuthenticateNTLMFixErrorHeader.\n");
	    }
	}
    }
}

void
authNTLMRequestFree(ntlm_request_t * ntlm_request)
{
    if (!ntlm_request)
	return;
    if (ntlm_request->ntlmnegotiate)
	xfree(ntlm_request->ntlmnegotiate);
    if (ntlm_request->authchallenge)
	xfree(ntlm_request->authchallenge);
    if (ntlm_request->ntlmauthenticate)
	xfree(ntlm_request->ntlmauthenticate);
    memPoolFree(ntlm_request_pool, ntlm_request);
}

void
authNTLMAURequestFree(auth_user_request_t * auth_user_request)
{
    if (auth_user_request->scheme_data)
	authNTLMRequestFree((ntlm_request_t *) auth_user_request->scheme_data);
    auth_user_request->scheme_data = NULL;
}

void
authenticateNTLMFreeUser(auth_user_t * auth_user)
{
    dlink_node *link, *tmplink;
    ntlm_user_t *ntlm_user = auth_user->scheme_data;
    auth_user_hash_pointer *proxy_auth_hash;

    debug(29, 5) ("authenticateNTLMFreeUser: Clearing NTLM scheme data\n");
    if (ntlm_user->username)
	xfree(ntlm_user->username);
    /* were they linked in by one or more proxy-authenticate headers */
    link = ntlm_user->proxy_auth_list.head;
    while (link) {
	debug(29, 9) ("authenticateFreeProxyAuthUser: removing proxy_auth hash entry '%d'\n", link->data);
	proxy_auth_hash = link->data;
	tmplink = link;
	link = link->next;
	dlinkDelete(tmplink, &ntlm_user->proxy_auth_list);
	hash_remove_link(proxy_auth_cache, (hash_link *) proxy_auth_hash);
	/* free the key (usually the proxy_auth header) */
	xfree(proxy_auth_hash->key);
	memFree(proxy_auth_hash, MEM_AUTH_USER_HASH);
    }
    memPoolFree(ntlm_user_pool, ntlm_user);
    auth_user->scheme_data = NULL;
}

static stateful_helper_callback_t
authenticateNTLMHandleplaceholder(void *data, void *lastserver, char *reply)
{
    authenticateStateData *r = data;
    stateful_helper_callback_t result = S_HELPER_UNKNOWN;
    int valid;
    /* we should only be called for placeholder requests - which have no reply string */
    assert(reply == NULL);
    assert(r->auth_user_request);
    /* standard callback stuff */
    valid = cbdataValid(r->data);
    cbdataUnlock(r->data);
    /* call authenticateNTLMStart to retry this request */
    debug(29, 9) ("authenticateNTLMHandleplaceholder: calling authenticateNTLMStart\n");
    authenticateNTLMStart(r->auth_user_request, r->handler, r->data);
    authenticateStateFree(r);
    return result;
}

static stateful_helper_callback_t
authenticateNTLMHandleReply(void *data, void *lastserver, char *reply)
{
#if 0
    authenticateStatefulStateData *r = data;
#endif
    authenticateStateData *r = data;
    ntlm_helper_state_t *helperstate;
    int valid;
    stateful_helper_callback_t result = S_HELPER_UNKNOWN;
#if 0
    void *nextserver = NULL;
#endif
    char *t = NULL;
    auth_user_request_t *auth_user_request;
    auth_user_t *auth_user;
    ntlm_user_t *ntlm_user;
    ntlm_request_t *ntlm_request;
    debug(29, 9) ("authenticateNTLMHandleReply: Helper: '%d' {%s}\n", lastserver, reply ? reply : "<NULL>");
    valid = cbdataValid(r->data);
    cbdataUnlock(r->data);
    if (valid) {
	if (reply) {
	    /* seperate out the useful data */
	    if (strncasecmp(reply, "TT ", 3) == 0) {
		reply += 3;
		/* we have been given a Challenge */
		/* we should check we weren't given an empty challenge */
#if 0
		result = S_HELPER_RESERVE;
#endif
		/* copy the challenge to the state data */
		helperstate = helperStatefulServerGetData(lastserver);
		if (helperstate == NULL)
		    fatal("lost NTLm helper state! quitting\n");
		helperstate->challenge = xstrndup(reply, NTLM_CHALLENGE_SZ + 5);
		helperstate->challengeuses = 0;
		helperstate->renewed = squid_curtime;
		/* and we satisfy the request that happended on the refresh boundary */
		/* note this code is now in two places FIXME */
		assert(r->auth_user_request != NULL);
		assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
		auth_user_request = r->auth_user_request;
		ntlm_request = auth_user_request->scheme_data;
		assert(ntlm_request != NULL);
		result = S_HELPER_DEFER;
#if 0
		nextserver = lastserver;
#endif
		debug(29, 9) ("authenticateNTLMHandleReply: helper '%d'\n", lastserver);
		assert(ntlm_request->auth_state == AUTHENTICATE_STATE_NEGOTIATE);
//                auth_user->auth_data.ntlm_auth.auth_state = AUTHENTICATE_STATE_CHALLENGE;
		ntlm_request->authhelper = lastserver;
		ntlm_request->authchallenge = xstrndup(reply, NTLM_CHALLENGE_SZ + 5);
	    } else if (strncasecmp(reply, "AF ", 3) == 0) {
		/* we're finished, release the helper */
		reply += 3;
		assert(r->auth_user_request != NULL);
		assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
		auth_user_request = r->auth_user_request;
		assert(auth_user_request->scheme_data != NULL);
		ntlm_request = auth_user_request->scheme_data;
		auth_user = auth_user_request->auth_user;
		ntlm_user = auth_user_request->auth_user->scheme_data;
		assert(ntlm_user != NULL);
		result = S_HELPER_RELEASE;
		/* we only expect OK when finishing the handshake */
		assert(ntlm_request->auth_state == AUTHENTICATE_STATE_RESPONSE);
		ntlm_user->username = xstrndup(reply, MAX_LOGIN_SZ);
		ntlm_request->authhelper = NULL;
		auth_user->flags.credentials_ok = 1;	/* login ok */
	    } else if (strncasecmp(reply, "NA ", 3) == 0) {
		/* TODO: only work with auth_user here if it exists */
		assert(r->auth_user_request != NULL);
		assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
		auth_user_request = r->auth_user_request;
		auth_user = auth_user_request->auth_user;
		assert(auth_user != NULL);
		ntlm_user = auth_user->scheme_data;
		ntlm_request = auth_user_request->scheme_data;
		assert((ntlm_user != NULL) && (ntlm_request != NULL));
		/* todo: action of Negotiate state on error */
		result = S_HELPER_RELEASE;	/*some error has occured. no more requests */
		ntlm_request->authhelper = NULL;
		auth_user->flags.credentials_ok = 2;	/* Login/Usercode failed */
		debug(29, 4) ("authenticateNTLMHandleReply: Error validating user via NTLM.\n");
		ntlm_request->auth_state = AUTHENTICATE_STATE_NONE;
		if ((t = strchr(reply, ' ')))	/* strip after a space */
		    *t = '\0';
	    } else if (strncasecmp(reply, "BH ", 3) == 0) {
		/* TODO kick off a refresh process. This can occur after a YR or after
		 * a KK. If after a YR release the helper and resubmit the request via 
		 * Authenticate NTLM start. 
		 * If after a KK deny the user's request w/ 407 and mark the helper as 
		 * Needing YR. */
		assert(r->auth_user_request != NULL);
		assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
		auth_user_request = r->auth_user_request;
		auth_user = auth_user_request->auth_user;
		assert(auth_user != NULL);
		ntlm_user = auth_user->scheme_data;
		ntlm_request = auth_user_request->scheme_data;
		assert((ntlm_user != NULL) && (ntlm_request != NULL));
		result = S_HELPER_RELEASE;	/*some error has occured. no more requests for 
						 * this helper */
		helperstate = helperStatefulServerGetData(ntlm_request->authhelper);
		ntlm_request->authhelper = NULL;
		if (ntlm_request->auth_state == AUTHENTICATE_STATE_NEGOTIATE) {
		    /* The helper broke on YR. It automatically
		     * resets */
		    auth_user->flags.credentials_ok = 3;	/* cannot process */
		    debug(29, 1) ("authenticateNTLMHandleReply: Error obtaining challenge from helper: %d.\n", lastserver);
		    /* mark it for starving */
		    helperstate->starve = 1;
		    /* resubmit the request. This helper is currently busy, so we will get
		     * a different one. */
		    authenticateNTLMStart(auth_user_request, r->handler, r->data);
		} else {
		    /* the helper broke on a KK */
		    /* first the standard KK stuff */
		    auth_user->flags.credentials_ok = 2;	/* Login/Usercode failed */
		    debug(29, 4) ("authenticateNTLMHandleReply: Error validating user via NTLM.\n");
		    ntlm_request->auth_state = AUTHENTICATE_STATE_NONE;
		    if ((t = strchr(reply, ' ')))	/* strip after a space */
			*t = '\0';
		    /* now we mark the helper for resetting. */
		    helperstate->starve = 1;
		}
		ntlm_request->auth_state = AUTHENTICATE_STATE_NONE;
	    } else {
		/* TODO: only work with auth_user here if it exists */
		assert(r->auth_user_request != NULL);
		assert(r->auth_user_request->auth_user->auth_type == AUTH_NTLM);
		auth_user_request = r->auth_user_request;
		auth_user = auth_user_request->auth_user;
		assert(auth_user != NULL);
		ntlm_user = auth_user->scheme_data;
		ntlm_request = auth_user_request->scheme_data;
		assert((ntlm_user != NULL) && (ntlm_request != NULL));
		debug(29, 1) ("authenticateNTLMHandleReply: Unsupported helper response, '%s'\n", reply);
		/* restart the authentication process */
		ntlm_request->auth_state = AUTHENTICATE_STATE_NONE;
		auth_user->flags.credentials_ok = 3;	/* cannot process */
		ntlm_request->authhelper = NULL;
	    }
	} else {
	    fatal("authenticateNTLMHandleReply: called with no result string\n");
	}
	r->handler(r->data, NULL);
    } else {
	debug(29, 1) ("AuthenticateNTLMHandleReply: invalid callback data. Releasing helper '%d'.\n", lastserver);
	result = S_HELPER_RELEASE;
    }
    authenticateStateFree(r);
    debug(29, 9) ("NTLM HandleReply, telling stateful helper : %d\n", result);
    return result;
}

#if 0
static void
authenticateNTLMStateFree(authenticateNTLMStateData * r)
{
    cbdataFree(r);
}

#endif

static void
authenticateNTLMStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "NTLM Authenticator Statistics:\n");
    helperStatefulStats(sentry, ntlmauthenticators);
}

/* is a particular challenge still valid ? */
int
authenticateNTLMValidChallenge(ntlm_helper_state_t * helperstate)
{
    if (helperstate->challenge == NULL)
	return 0;
    return 1;
}

/* does our policy call for changing the challenge now? */
int
authenticateNTLMChangeChallenge(ntlm_helper_state_t * helperstate)
{
    /* don't check for invalid challenges just for expiry choices */
    /* this is needed because we have to starve the helper until all old
     * requests have been satisfied */
    if (helperstate->challengeuses > ntlmConfig->challengeuses)
	return 1;
    if (helperstate->renewed + ntlmConfig->challengelifetime >= squid_curtime)
	return 1;
    return 0;
}

/* send the initial data to a stateful ntlm authenticator module */
static void
authenticateNTLMStart(auth_user_request_t * auth_user_request, RH * handler, void *data)
{
#if 0
    authenticateStatefulStateData *r = NULL;
#endif
    authenticateStateData *r = NULL;
    helper_stateful_server *server;
    ntlm_helper_state_t *helperstate;
    char buf[8192];
    char *sent_string = NULL;
    ntlm_user_t *ntlm_user;
    ntlm_request_t *ntlm_request;
    auth_user_t *auth_user;

    assert(auth_user_request);
    auth_user = auth_user_request->auth_user;
    ntlm_user = auth_user->scheme_data;
    ntlm_request = auth_user_request->scheme_data;
    assert(ntlm_user);
    assert(ntlm_request);
    assert(handler);
    assert(data);
    assert(auth_user->auth_type = AUTH_NTLM);
    debug(29, 9) ("authenticateNTLMStart: auth state '%d'\n", ntlm_request->auth_state);
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NEGOTIATE:
	sent_string = xstrdup(ntlm_request->ntlmnegotiate);
	break;
    case AUTHENTICATE_STATE_RESPONSE:
	sent_string = xstrdup(ntlm_request->ntlmauthenticate);
	assert(ntlm_request->authhelper);
	debug(29, 9) ("authenticateNTLMStart: Asking NTLMauthenticator '%d'.\n", ntlm_request->authhelper);
	break;
    default:
	fatal("Invalid authenticate state for NTLMStart");
    }

    while (!xisspace(*sent_string))	/*trim NTLM */
	sent_string++;

    while (xisspace(*sent_string))	/*trim leading spaces */
	sent_string++;

    debug(29, 9) ("authenticateNTLMStart: state '%d'\n", ntlm_request->auth_state);
    debug(29, 9) ("authenticateNTLMStart: '%s'\n", sent_string);
    if (ntlmConfig->authenticate == NULL) {
	debug(29, 0) ("authenticateNTLMStart: no NTLM program specified:'%s'\n", sent_string);
//      handler(data,0, NULL);
	handler(data, NULL);
	return;
    }
#ifdef NTLMHELPPROTOCOLV2
    r = CBDATA_ALLOC(authenticateStateData, NULL);
    r->handler = handler;
    cbdataLock(data);
    r->data = data;
    r->auth_user_request = auth_user_request;
    snprintf(buf, 8192, "%s\n", sent_string);
    helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, ntlm_request->authhelper);
    debug(29, 9) ("authenticateNTLMstart: finished\n");
#else
    /* this is ugly TODO: move the challenge generation routines to their own function and
     * tidy the logic up to make use of the efficiency we now have */
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NEGOTIATE:
	/*  
	 * 1: get a helper server
	 * 2: does it have a challenge?
	 * 3: tell it to get a challenge, or give ntlmauthdone the challenge
	 */
	server = helperStatefulDefer(ntlmauthenticators);
	helperstate = server ? helperStatefulServerGetData(server) : NULL;
	while ((server != NULL) &&
	    authenticateNTLMChangeChallenge(helperstate)) {
	    /* flag this helper for challenge changing */
	    helperstate->starve = 1;
	    /* and release the deferred request */
	    helperStatefulReleaseServer(server);
	    server = helperStatefulDefer(ntlmauthenticators);
	    if (server != NULL)
		helperstate = helperStatefulServerGetData(server);
	}
	if (server == NULL)
	    debug(29, 9) ("unable to get a deferred ntlm helper... all helpers are refreshing challenges. Queuing as a placeholder request.\n");

	ntlm_request->authhelper = server;
	/* tell the log what helper we have been given */
	debug(29, 9) ("authenticateNTLMStart: helper '%d' assigned\n", server);
	/* valid challenge? */
	if ((server == NULL) || !authenticateNTLMValidChallenge(helperstate)) {
	    r = CBDATA_ALLOC(authenticateStateData, NULL);
	    r->handler = handler;
	    cbdataLock(data);
	    r->data = data;
	    r->auth_user_request = auth_user_request;
	    if (server == NULL) {
		helperStatefulSubmit(ntlmauthenticators, NULL, authenticateNTLMHandleplaceholder, r, ntlm_request->authhelper);
	    } else {
		snprintf(buf, 8192, "YR\n");
		helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, ntlm_request->authhelper);
	    }
	} else {
	    /* we have a valid challenge */
	    /* TODO: turn the below into a function and call from here and handlereply */
	    /* increment the challenge uses */
	    helperstate->challengeuses++;
	    /* assign the challenge */
	    ntlm_request->authchallenge =
		xstrndup(helperstate->challenge, NTLM_CHALLENGE_SZ + 5);
	    handler(data, NULL);
	}

	break;
    case AUTHENTICATE_STATE_RESPONSE:
	r = CBDATA_ALLOC(authenticateStateData, NULL);
	r->handler = handler;
	cbdataLock(data);
	r->data = data;
	r->auth_user_request = auth_user_request;
	snprintf(buf, 8192, "KK %s\n", sent_string);
	helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, ntlm_request->authhelper);
	debug(29, 9) ("authenticateNTLMstart: finished\n");
	break;
    default:
	fatal("Invalid authenticate state for NTLMStart");
    }
#endif
}

/* callback used by stateful helper routines */
int
authenticateNTLMHelperServerAvailable(void *data)
{
    ntlm_helper_state_t *statedata = data;
    if (statedata != NULL) {
	if (statedata->starve) {
	    debug(29, 4) ("authenticateNTLMHelperServerAvailable: starving - returning 0\n");
	    return 0;
	} else {
	    debug(29, 4) ("authenticateNTLMHelperServerAvailable: not starving - returning 1\n");
	    return 1;
	}
    }
    debug(29, 4) ("authenticateNTLMHelperServerAvailable: no state data - returning 0\n");
    return 0;
}

void
authenticateNTLMHelperServerOnEmpty(void *data)
{
    ntlm_helper_state_t *statedata = data;
    if (statedata == NULL)
	return;
    if (statedata->starve) {
	/* we have been starving the helper */
	debug(29, 9) ("authenticateNTLMHelperServerOnEmpty: resetting challenge details\n");
	statedata->starve = 0;
	statedata->challengeuses = 0;
	statedata->renewed = 0;
	xfree(statedata->challenge);
	statedata->challenge = NULL;
    }
}


/* clear the NTLM helper of being reserved for future requests */
void
authenticateNTLMReleasehelper(auth_user_request_t * auth_user_request)
{
    ntlm_request_t *ntlm_request;
    assert(auth_user_request->auth_user->auth_type == AUTH_NTLM);
    assert(auth_user_request->scheme_data != NULL);
    ntlm_request = auth_user_request->scheme_data;
    debug(29, 9) ("authenticateNTLMReleasehelper: releasing helper '%d'\n", ntlm_request->authhelper);
    helperStatefulReleaseServer(ntlm_request->authhelper);
    ntlm_request->authhelper = NULL;
}

/* clear any connection related authentication details */
void
authenticateNTLMOnCloseConnection(ConnStateData * conn)
{
    ntlm_request_t *ntlm_request;
    assert(conn != NULL);
    if (conn->auth_user_request != NULL) {
	assert(conn->auth_user_request->scheme_data != NULL);
	ntlm_request = conn->auth_user_request->scheme_data;
	if (ntlm_request->authhelper != NULL)
	    authenticateNTLMReleasehelper(conn->auth_user_request);
	/* unlock the connection based lock */
	debug(29, 9) ("authenticateNTLMOnCloseConnection: Unlocking auth_user from the connection.\n");
	authenticateAuthUserRequestUnlock(conn->auth_user_request);
	conn->auth_user_request = NULL;
    }
}

/* authenticateUserUsername: return a pointer to the username in the */
char *
authenticateNTLMUsername(auth_user_t * auth_user)
{
    ntlm_user_t *ntlm_user = auth_user->scheme_data;
    if (ntlm_user)
	return ntlm_user->username;
    return NULL;
}


/*
 * Decode an NTLM [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */

void
authenticateDecodeNTLMAuth(auth_user_request_t * auth_user_request, const char *proxy_auth)
{
    dlink_node *node;
    assert(auth_user_request->auth_user == NULL);
    auth_user_request->auth_user = authenticateAuthUserNew("ntlm");
    auth_user_request->auth_user->auth_type = AUTH_NTLM;
    auth_user_request->auth_user->scheme_data = memPoolAlloc(ntlm_user_pool);
    auth_user_request->scheme_data = memPoolAlloc(ntlm_request_pool);
    /* lock for the auth_user_request link */
    authenticateAuthUserLock(auth_user_request->auth_user);
    node = dlinkNodeNew();
    dlinkAdd(auth_user_request, node, &auth_user_request->auth_user->requests);

    /* all we have to do is identify that it's NTLM - the helper does the rest */
    debug(29, 9) ("authenticateDecodeNTLMAuth: NTLM authentication\n");
    return;
}

int
authenticateNTLMcmpUsername(ntlm_user_t * u1, ntlm_user_t * u2)
{
    return strcmp(u1->username, u2->username);
}

void
authenticateProxyAuthCacheAddLink(const char *key, auth_user_t * auth_user)
{
    auth_user_hash_pointer *proxy_auth_hash;
    ntlm_user_t *ntlm_user;
    proxy_auth_hash =
	memAllocate(MEM_AUTH_USER_HASH);
    proxy_auth_hash->key = xstrdup(key);
    proxy_auth_hash->auth_user = auth_user;
    ntlm_user = auth_user->scheme_data;
    dlinkAddTail(proxy_auth_hash, &proxy_auth_hash->link,
	&ntlm_user->proxy_auth_list);
    hash_join(proxy_auth_cache, (hash_link *) proxy_auth_hash);
}


int
authNTLMAuthenticated(auth_user_request_t * auth_user_request)
{
    ntlm_request_t *ntlm_request = auth_user_request->scheme_data;
    if (ntlm_request->auth_state == AUTHENTICATE_STATE_DONE)
	return 1;
    debug(29, 9) ("User not fully authenticated.\n");
    return 0;
}

#if 0
static acl_proxy_auth_user *
authenticateNTLMAuthenticateUser(void *data, const char *proxy_auth, ConnStateData * conn)
#else
static void
authenticateNTLMAuthenticateUser(auth_user_request_t * auth_user_request, request_t * request, ConnStateData * conn, http_hdr_type type)
#endif
{
    const char *proxy_auth;
    auth_user_hash_pointer *usernamehash, *proxy_auth_hash = NULL;
    auth_user_t *auth_user;
    ntlm_request_t *ntlm_request;
    ntlm_user_t *ntlm_user;
    LOCAL_ARRAY(char, ntlmhash, NTLM_CHALLENGE_SZ * 2);
    /* get header */
    proxy_auth = httpHeaderGetStr(&request->header, type);

    auth_user = auth_user_request->auth_user;
    assert(auth_user);
    assert(auth_user->auth_type == AUTH_NTLM);
    assert(auth_user->scheme_data != NULL);
    assert(auth_user_request->scheme_data != NULL);
    ntlm_user = auth_user->scheme_data;
    ntlm_request = auth_user_request->scheme_data;
    switch (ntlm_request->auth_state) {
    case AUTHENTICATE_STATE_NONE:
	/* we've recieved a negotiate request. pass to a helper */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state ntlm none. %s\n",
	    proxy_auth);
	ntlm_request->auth_state = AUTHENTICATE_STATE_NEGOTIATE;
	ntlm_request->ntlmnegotiate = xstrndup(proxy_auth, NTLM_CHALLENGE_SZ + 5);
	conn->auth_type = AUTH_NTLM;
	conn->auth_user_request = auth_user_request;
	/* and lock for the connection duration */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: Locking auth_user from the connection.\n");
	authenticateAuthUserRequestLock(auth_user_request);
	return;
	break;
    case AUTHENTICATE_STATE_NEGOTIATE:
	ntlm_request->auth_state = AUTHENTICATE_STATE_CHALLENGE;
	return;
	break;
    case AUTHENTICATE_STATE_CHALLENGE:
	/* we should have recieved a NTLM challenge. pass it to the same 
	 * helper process */
	debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state challenge with header %s.\n", proxy_auth);
	/* do a cache lookup here. If it matches it's a successful ntlm 
	 * challenge - release the helper and use the existing auth_user 
	 * details. */
	if (strncmp("NTLM ", proxy_auth, 5) == 0) {
	    ntlm_request->ntlmauthenticate = xstrdup(proxy_auth);
	} else {
	    fatal("Incorrect scheme in auth header\n");
	    /* TODO: more fault tolerance.. reset the auth scheme here */
	}
	/* cache entries have authenticateauthheaderchallengestring */
	snprintf(ntlmhash, sizeof(ntlmhash) - 1, "%s%s",
	    ntlm_request->ntlmauthenticate,
	    ntlm_request->authchallenge);
	/* see if we already know this user's authenticate */
	debug(29, 9) ("aclMatchProxyAuth: cache lookup with key '%s'\n", ntlmhash);
	assert(proxy_auth_cache != NULL);
	proxy_auth_hash = hash_lookup(proxy_auth_cache, ntlmhash);
	if (!proxy_auth_hash) {	/* not in the hash table */
	    debug(29, 4) ("authenticateNTLMAuthenticateUser: proxy-auth cache miss.\n");
	    ntlm_request->auth_state = AUTHENTICATE_STATE_RESPONSE;
	    /* verify with the ntlm helper */
	} else {
	    debug(29, 4) ("authenticateNTLMAuthenticateUser: ntlm proxy-auth cache hit\n");
	    /* throw away the temporary entry */
	    authenticateNTLMReleasehelper(auth_user_request);
	    authenticateAuthUserMerge(auth_user, proxy_auth_hash->auth_user);
	    auth_user = proxy_auth_hash->auth_user;
	    auth_user_request->auth_user = auth_user;
	    ntlm_request->auth_state = AUTHENTICATE_STATE_DONE;
	    /* we found one */
	    debug(29, 9) ("found matching cache entry\n");
	    assert(auth_user->auth_type == AUTH_NTLM);
	    /* get the existing entries details */
	    ntlm_user = auth_user->scheme_data;
	    debug(29, 9) ("Username to be used is %s\n",
		ntlm_user->username);
	    auth_user->flags.credentials_ok = 1;	/* authenticated ok */
	    /* on ntlm auth we do not unlock the auth_user until the
	     * connection is dropped. Thank MS for this quirk */
	    auth_user->expiretime = current_time.tv_sec;
	    auth_user->ip_expiretime = squid_curtime;
	}
	return;
	break;
    case AUTHENTICATE_STATE_RESPONSE:
	/* auth-challenge pair cache miss. We've just got the response */
	/*add to cache and let them through */
	ntlm_request->auth_state = AUTHENTICATE_STATE_DONE;
	/* this connection is authenticated */
	debug(29, 4) ("authenticated\nch    %s\nauth     %s\nauthuser %s\n",
	    ntlm_request->authchallenge,
	    ntlm_request->ntlmauthenticate,
	    ntlm_user->username);
	/* cache entries have authenticateauthheaderchallengestring */
	snprintf(ntlmhash, sizeof(ntlmhash) - 1, "%s%s",
	    ntlm_request->ntlmauthenticate,
	    ntlm_request->authchallenge);
	/* see if this is an existing user with a different proxy_auth 
	 * string */
	if ((usernamehash = hash_lookup(proxy_auth_username_cache,
		    ntlm_user->username))) {
	    while ((usernamehash->auth_user->auth_type !=
		    auth_user->auth_type) && (usernamehash->next) &&
		!authenticateNTLMcmpUsername(usernamehash->auth_user->scheme_data, ntlm_user))
		usernamehash = usernamehash->next;
	    if (usernamehash->auth_user->auth_type == auth_user->auth_type) {
		/*
		 * add another link from the new proxy_auth to the
		 * auth_user structure and update the information */
		assert(proxy_auth_hash == NULL);
		authenticateProxyAuthCacheAddLink(ntlmhash, usernamehash->auth_user);
		/* we can't seamlessly recheck the username due to the 
		 * challenge nature of the protocol. Just free the 
		 * temporary auth_user */
		authenticateAuthUserMerge(auth_user, usernamehash->auth_user);
		auth_user = usernamehash->auth_user;
		auth_user_request->auth_user = auth_user;
#if 0
		conn->auth_user = auth_user;
#endif
	    }
	} else {
	    /* store user in hash's */
	    authenticateUserNameCacheAdd(auth_user);
	    authenticateProxyAuthCacheAddLink(ntlmhash, auth_user);
	}
	/* set these to now because this is either a new login from an 
	 * existing user or a new user */
	auth_user->expiretime = current_time.tv_sec;
	auth_user->ip_expiretime = squid_curtime;
	auth_user->flags.credentials_ok = 1;	/*authenticated ok */
	return;
	break;
    case AUTHENTICATE_STATE_DONE:
	fatal("authenticateNTLMAuthenticateUser: unexpect auth state DONE! Report a bug to the squid developers.\n");
#if 0				/* done in acl.c */
    case AUTHENTICATE_STATE_DONE:
	debug(28, 5) ("aclMatchProxyAuth: connection in state Done. using connection credentials for the request. \n");
	/* is it working right? */
	assert(checklist->auth_user == NULL);
	assert(checklist->conn->auth_user != NULL);
	/* we have a valid username. */
	auth_user = checklist->conn->auth_user;
	/* store the username in the request for logging */
	xstrncpy(checklist->request->authuser,
	    auth_user->auth_data.ntlm_auth.username,
	    USER_IDENT_SZ);
	if (auth_user->expiretime + Config.authenticateTTL > current_time.tv_sec
	    ) {
	    auth_user->expiretime = current_time.tv_sec;
	} else {
	    //user passed externa; authentication in every case to get here. f.
	    Let it through
	}			/* we don't unlock the auth_user until the connection is dropped. Thank
				 * MS for this quirk. */ if (authenticateCheckAuthUserIP(checklist->src_addr, auth_user)) {
	    /* Once the match is completed we have finished with the
	     * auth_user structure */
	    /* check to see if we have matched the user-acl before */
	    return aclCacheMatchAcl(&auth_user->proxy_match_cache, acltype,
		data, auth_user->auth_data.ntlm_auth.username);
	} else {
	    return 0;
	}
	break;
#endif
    }

    return;
}
