
/*
 * $Id: auth_ntlm.cc,v 1.48 2005/09/14 17:10:39 serassio Exp $
 *
 * DEBUG: section 29    NTLM Authenticator
 * AUTHOR: Robert Collins
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
#include "auth_ntlm.h"
#include "authenticate.h"
#include "Store.h"
#include "client_side.h"
#include "HttpReply.h"
#include "HttpRequest.h"
/* TODO remove this include */
#include "ntlmScheme.h"

static void
authenticateStateFree(authenticateStateData * r)
{
    r->auth_user_request->unlock();
    r->auth_user_request = NULL;
    cbdataFree(r);
}

/* NTLM Scheme */
static HLPSCB authenticateNTLMHandleReply;
static HLPSCB authenticateNTLMHandleplaceholder;
static AUTHSSTATS authenticateNTLMStats;

/* helper callbacks to handle per server state data */
static HLPSAVAIL authenticateNTLMHelperServerAvailable;
static HLPSONEQ authenticateNTLMHelperServerOnEmpty;

static statefulhelper *ntlmauthenticators = NULL;

CBDATA_TYPE(authenticateStateData);

static int authntlm_initialised = 0;

static MemAllocatorProxy *ntlm_helper_state_pool = NULL;
static MemAllocatorProxy *ntlm_user_hash_pool = NULL;

static auth_ntlm_config ntlmConfig;

static hash_table *proxy_auth_cache = NULL;

/*
 *
 * Private Functions
 *
 */

/* move to ntlmScheme.cc */
void
ntlmScheme::done()
{
    /* TODO: this should be a Config call. */
    debug(29, 2) ("authNTLMDone: shutting down NTLM authentication.\n");

    if (ntlmauthenticators)
        helperStatefulShutdown(ntlmauthenticators);

    authntlm_initialised = 0;

    if (!shutting_down)
        return;

    if (ntlmauthenticators)
        helperStatefulFree(ntlmauthenticators);

    ntlmauthenticators = NULL;

#if DEBUGSHUTDOWN

    if (ntlm_helper_state_pool) {
        delete ntlm_helper_state_pool;
        ntlm_helper_state_pool = NULL;
    }

    /* Removed for some reason..
        if (ntlm_user_pool) {
    	delete ntlm_user_pool;ntlm_user_pool = NULL;
        }
        */

#endif
    debug(29, 2) ("authNTLMDone: NTLM authentication Shutdown.\n");
}

/* free any allocated configuration details */
void
AuthNTLMConfig::done()
{
    if (authenticate)
        wordlistDestroy(&authenticate);
}

void
AuthNTLMConfig::dump(StoreEntry * entry, const char *name, AuthConfig * scheme)
{
    wordlist *list = authenticate;
    storeAppendPrintf(entry, "%s %s", name, "ntlm");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n%s %s children %d\n%s %s max_challenge_reuses %d\n%s %s max_challenge_lifetime %d seconds\n",
                      name, "ntlm", authenticateChildren,
                      name, "ntlm", challengeuses,
                      name, "ntlm", (int) challengelifetime);

}

AuthNTLMConfig::AuthNTLMConfig()
{
    /* TODO Move into initialisation list */
    authenticateChildren = 5;
    challengeuses = 0;
    challengelifetime = 60;
}

void
AuthNTLMConfig::parse(AuthConfig * scheme, int n_configured, char *param_str)
{
    if (strcasecmp(param_str, "program") == 0) {
        if (authenticate)
            wordlistDestroy(&authenticate);

        parse_wordlist(&authenticate);

        requirePathnameExists("authparam ntlm program", authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        parse_int(&authenticateChildren);
    } else if (strcasecmp(param_str, "max_challenge_reuses") == 0) {
        parse_int(&challengeuses);
    } else if (strcasecmp(param_str, "max_challenge_lifetime") == 0) {
        parse_time_t(&challengelifetime);
    } else {
        debug(28, 0) ("unrecognised ntlm auth scheme parameter '%s'\n", param_str);
    }

    /*
     * disable client side request pipelining. There is a race with
     * NTLM when the client sends a second request on an NTLM
     * connection before the authenticate challenge is sent. With
     * this patch, the client may fail to authenticate, but squid's
     * state will be preserved.  Caveats: this should be a post-parse
     * test, but that can wait for the modular parser to be integrated.
     */
    if (authenticate)
        Config.onoff.pipeline_prefetch = 0;
}

const char *
AuthNTLMConfig::type() const
{
    return ntlmScheme::GetInstance().type();
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
AuthNTLMConfig::init(AuthConfig * scheme)
{
    static int ntlminit = 0;

    if (authenticate) {
        if (!ntlm_helper_state_pool)
            ntlm_helper_state_pool = new MemAllocatorProxy("NTLM Helper State data", sizeof(ntlm_helper_state_t));

        if (!ntlm_user_hash_pool)

            ntlm_user_hash_pool = new MemAllocatorProxy("NTLM Header Hash Data", sizeof(struct ProxyAuthCachePointer));

        authntlm_initialised = 1;

        if (ntlmauthenticators == NULL)
            ntlmauthenticators = helperStatefulCreate("ntlmauthenticator");

        if (!proxy_auth_cache)
            proxy_auth_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);

        assert(proxy_auth_cache);

        ntlmauthenticators->cmdline = authenticate;

        ntlmauthenticators->n_to_start = authenticateChildren;

        ntlmauthenticators->ipc_type = IPC_STREAM;

        ntlmauthenticators->datapool = ntlm_helper_state_pool;

        ntlmauthenticators->IsAvailable = authenticateNTLMHelperServerAvailable;

        ntlmauthenticators->OnEmptyQueue = authenticateNTLMHelperServerOnEmpty;

        helperStatefulOpenServers(ntlmauthenticators);

        /*
         * TODO: In here send the initial YR to preinitialise the
         * challenge cache
         */
        /*
         * Think about this... currently we ask when the challenge
         * is needed. Better?
         */
        if (!ntlminit) {
            cachemgrRegister("ntlmauthenticator",
                             "NTLM User Authenticator Stats",
                             authenticateNTLMStats, 0, 1);
            ntlminit++;
        }

        CBDATA_INIT_TYPE(authenticateStateData);
    }
}

bool
AuthNTLMConfig::active() const
{
    return authntlm_initialised == 1;
}

bool
AuthNTLMConfig::configured() const
{
    if ((authenticate != NULL) && (authenticateChildren != 0) && (challengeuses > -1) && (challengelifetime > -1)) {
        debug(29, 9) ("authNTLMConfigured: returning configured\n");
        return true;
    }

    debug(29, 9) ("authNTLMConfigured: returning unconfigured\n");
    return false;
}

/* NTLM Scheme */
int
AuthNTLMUserRequest::module_direction()
{
    /* null auth_user is checked for by authenticateDirection */

    switch (auth_state) {

        /* no progress at all. */

    case AUTHENTICATE_STATE_NONE:
        debug(29, 1) ("AuthNTLMUserRequest::direction: called before NTLM Authenticate!. Report a bug to squid-dev.\n");
        /* fall thru */

    case AUTHENTICATE_STATE_FAILED:
        return -2;

        /* send to helper */

    case AUTHENTICATE_STATE_NEGOTIATE:

        /*send to helper */

    case AUTHENTICATE_STATE_RESPONSE:
        return -1;

        /* send to client */

    case AUTHENTICATE_STATE_CHALLENGE:
        return 1;

        /* do nothing.. */

    case AUTHENTICATE_STATE_DONE:
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
AuthNTLMConfig::fixHeader(auth_user_request_t *auth_user_request, HttpReply *rep, http_hdr_type type, HttpRequest * request)
{
    AuthNTLMUserRequest *ntlm_request;

    if (!request->flags.proxy_keepalive)
        return;

    if (authenticate) {
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
            ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
            assert (ntlm_request);

            switch (ntlm_request->auth_state) {

            case AUTHENTICATE_STATE_NONE:

            case AUTHENTICATE_STATE_FAILED:
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
                request->flags.must_keepalive = 1;
                break;

            default:
                debug(29, 0) ("authenticateNTLMFixErrorHeader: state %d.\n", ntlm_request->auth_state);
                fatal("unexpected state in AuthenticateNTLMFixErrorHeader.\n");
            }
        }
    }
}

NTLMUser::~NTLMUser()
{
    dlink_node *link, *tmplink;
    ProxyAuthCachePointer *proxy_auth_hash;
    debug(29, 5) ("NTLMUser::~NTLMUser: Clearing NTLM scheme data\n");

    /* were they linked in by one or more proxy-authenticate headers */
    link = proxy_auth_list.head;

    while (link) {
        debug(29, 9) ("authenticateFreeProxyAuthUser: removing proxy_auth hash entry '%p'\n", link->data);
        proxy_auth_hash = static_cast<ProxyAuthCachePointer *>(link->data);
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, &proxy_auth_list);
        hash_remove_link(proxy_auth_cache, (hash_link *) proxy_auth_hash);
        /* free the key (usually the proxy_auth header) */
        xfree(proxy_auth_hash->key);
        ntlm_user_hash_pool->free(proxy_auth_hash);
    }

}

static stateful_helper_callback_t
authenticateNTLMHandleplaceholder(void *data, void *lastserver, char *reply)
{
    authenticateStateData *r = static_cast<authenticateStateData *>(data);
    stateful_helper_callback_t result = S_HELPER_UNKNOWN;
    /* we should only be called for placeholder requests - which have no reply string */
    assert(reply == NULL);
    assert(r->auth_user_request);
    /* standard callback stuff */

    if (!cbdataReferenceValid(r->data)) {
        debug(29, 1) ("AuthenticateNTLMHandlePlacheholder: invalid callback data.\n");
        return result;
    }

    /* call authenticateNTLMStart to retry this request */
    debug(29, 9) ("authenticateNTLMHandleplaceholder: calling authenticateNTLMStart\n");

    r->auth_user_request->start(r->handler, r->data);

    cbdataReferenceDone(r->data);

    authenticateStateFree(r);

    return result;
}

static stateful_helper_callback_t
authenticateNTLMHandleReply(void *data, void *lastserver, char *reply)
{
    authenticateStateData *r = static_cast<authenticateStateData *>(data);
    ntlm_helper_state_t *helperstate;
    stateful_helper_callback_t result = S_HELPER_UNKNOWN;
    auth_user_request_t *auth_user_request;
    auth_user_t *auth_user;
    ntlm_user_t *ntlm_user;
    AuthNTLMUserRequest *ntlm_request;
    debug(29, 9) ("authenticateNTLMHandleReply: Helper: '%p' {%s}\n", lastserver, reply ? reply : "<NULL>");

    if (!cbdataReferenceValid(r->data)) {
        debug(29, 1) ("AuthenticateNTLMHandleReply: invalid callback data. Releasing helper '%p'.\n", lastserver);
        cbdataReferenceDone(r->data);
        authenticateStateFree(r);
        debug(29, 9) ("NTLM HandleReply, telling stateful helper : %d\n", S_HELPER_RELEASE);
        return S_HELPER_RELEASE;
    }

    if (!reply) {
        /*
         * TODO: this occurs when a helper crashes. We should clean
         * up that helpers resources and queued requests.
         */
        fatal("authenticateNTLMHandleReply: called with no result string\n");
    }

    /* seperate out the useful data */
    if (strncasecmp(reply, "TT ", 3) == 0) {
        reply += 3;
        /* we have been given a Challenge */
        /* we should check we weren't given an empty challenge */
        /* copy the challenge to the state data */
        helperstate = static_cast<ntlm_helper_state_t *>(helperStatefulServerGetData(static_cast<helper_stateful_server *>(lastserver)));

        if (helperstate == NULL)
            fatal("lost NTLM helper state! quitting\n");

        helperstate->challenge = xstrdup(reply);

        helperstate->challengeuses = 0;

        helperstate->renewed = squid_curtime;

        /* and we satisfy the request that happended on the refresh boundary */
        /* note this code is now in two places FIXME */
        assert(r->auth_user_request != NULL);

        assert(r->auth_user_request->user()->auth_type == AUTH_NTLM);

        auth_user_request = r->auth_user_request;

        ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);

        assert(ntlm_request != NULL);

        result = S_HELPER_DEFER;

        /* reserve the server for future authentication */
        ntlm_request->authserver_deferred = 1;

        debug(29, 9) ("authenticateNTLMHandleReply: helper '%p'\n", lastserver);

        assert(ntlm_request->auth_state == AUTHENTICATE_STATE_NEGOTIATE);

        ntlm_request->authserver = static_cast<helper_stateful_server *>(lastserver);

        ntlm_request->authchallenge = xstrdup(reply);
    } else if (strncasecmp(reply, "AF ", 3) == 0) {
        /* we're finished, release the helper */
        reply += 3;
        assert(r->auth_user_request != NULL);
        assert(r->auth_user_request->user()->auth_type == AUTH_NTLM);
        auth_user_request = r->auth_user_request;
        ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
        assert(ntlm_request);
        auth_user = auth_user_request->user();
        ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user_request->user());
        assert(ntlm_user != NULL);
        result = S_HELPER_RELEASE;
        /* we only expect OK when finishing the handshake */
        assert(ntlm_request->auth_state == AUTHENTICATE_STATE_RESPONSE);
        ntlm_user->username(xstrdup(reply));
        ntlm_request->authserver = NULL;
#ifdef NTLM_FAIL_OPEN

    } else if (strncasecmp(reply, "LD ", 3) == 0) {
        /* This is a variant of BH, which rather than deny access
         * allows the user through. The helper is starved and then refreshed
         * via YR, all pending authentications are likely to fail also.
         * It is meant for those helpers which occasionally fail for
         * no reason at all (casus belli, NTLMSSP helper on NT domain,
         * failing about 1 auth out of 1k.
         * The code is a merge from the BH case with snippets of the AF
         * case */
        /* AF code: mark user as authenticated */
        reply += 3;
        assert(r->auth_user_request != NULL);
        assert(r->auth_user_request->user()->auth_type == AUTH_NTLM);
        auth_user_request = r->auth_user_request;
        ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
        assert(ntlm_request);
        auth_user = auth_user_request->user();
        ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user_request->user());
        assert(ntlm_user != NULL);
        result = S_HELPER_RELEASE;
        /* we only expect LD when finishing the handshake */
        assert(ntlm_request->auth_state == AUTHENTICATE_STATE_RESPONSE);
        ntlm_user->username_ = xstrdup(reply);
        helperstate = static_cast<ntlm_helper_state_t *>(helperStatefulServerGetData(ntlm_request->authserver));
        ntlm_request->authserver = NULL;
        /* BH code: mark helper as broken */
        /* mark it for starving */
        helperstate->starve = 1;
#endif

    } else if (strncasecmp(reply, "NA ", 3) == 0) {
        /* TODO: only work with auth_user here if it exists */
        assert(r->auth_user_request != NULL);
        assert(r->auth_user_request->user()->auth_type == AUTH_NTLM);
        auth_user_request = r->auth_user_request;
        auth_user = auth_user_request->user();
        assert(auth_user != NULL);
        ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
        ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
        assert((ntlm_user != NULL) && (ntlm_request != NULL));
        /* todo: action of Negotiate state on error */
        result = S_HELPER_RELEASE;	/*some error has occured. no more requests */
        ntlm_request->authserver = NULL;
        debug(29, 4) ("authenticateNTLMHandleReply: Error validating user via NTLM. Error returned '%s'\n", reply);
        ntlm_request->auth_state = AUTHENTICATE_STATE_FAILED;
        reply += 3;

        if (*reply)
            auth_user_request->setDenyMessage(reply);
    } else if (strncasecmp(reply, "NA", 2) == 0) {
        /* NTLM Helper protocol violation! */
        fatal("NTLM Helper returned invalid response \"NA\" - a error message MUST be attached\n");
    } else if (strncasecmp(reply, "BH ", 3) == 0) {
        /* TODO kick off a refresh process. This can occur after a YR or after
         * a KK. If after a YR release the helper and resubmit the request via 
         * Authenticate NTLM start. 
         * If after a KK deny the user's request w/ 407 and mark the helper as 
         * Needing YR. */
        assert(r->auth_user_request != NULL);
        assert(r->auth_user_request->user()->auth_type == AUTH_NTLM);
        auth_user_request = r->auth_user_request;
        auth_user = auth_user_request->user();
        assert(auth_user != NULL);
        ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
        ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
        assert((ntlm_user != NULL) && (ntlm_request != NULL));
        /*some error has occured. no more requests for
                                               				                					 * this helper */
        result = S_HELPER_RELEASE;
        assert(ntlm_request->authserver ? ntlm_request->authserver == lastserver : 1);
        helperstate = static_cast<ntlm_helper_state_t *>(helperStatefulServerGetData(ntlm_request->authserver));
        ntlm_request->authserver = NULL;

        if (ntlm_request->auth_state == AUTHENTICATE_STATE_NEGOTIATE) {
            /* The helper broke on YR. It automatically
             * resets */
            debug(29, 1) ("authenticateNTLMHandleReply: Error obtaining challenge from helper: %p. Error returned '%s'\n", lastserver, reply);
            /* mark it for starving */
            helperstate->starve = 1;
            /* resubmit the request. This helper is currently busy, so we will get
             * a different one. Our auth state stays the same */
            auth_user_request->start(r->handler, r->data);
            /* don't call the callback */
            cbdataReferenceDone(r->data);
            authenticateStateFree(r);
            debug(29, 9) ("NTLM HandleReply, telling stateful helper : %d\n", result);
            return result;
        }

        /* the helper broke on a KK */
        /* first the standard KK stuff */
        debug(29, 4) ("authenticateNTLMHandleReply: Error validating user via NTLM. Error returned '%s'\n", reply);

        /* now we mark the helper for resetting. */
        helperstate->starve = 1;

        ntlm_request->auth_state = AUTHENTICATE_STATE_FAILED;

        reply += 3;

        if (*reply)
            auth_user_request->setDenyMessage(reply);
    } else {
        /* TODO: only work with auth_user here if it exists */
        /* TODO: take the request state into consideration */
        assert(r->auth_user_request != NULL);
        assert(r->auth_user_request->user()->auth_type == AUTH_NTLM);
        auth_user_request = r->auth_user_request;
        auth_user = auth_user_request->user();
        assert(auth_user != NULL);
        ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
        ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
        assert((ntlm_user != NULL) && (ntlm_request != NULL));
        debug(29, 1) ("authenticateNTLMHandleReply: *** Unsupported helper response ***, '%s'\n", reply);
        /* **** NOTE THIS CODE IS EFFECTIVELY UNTESTED **** */
        /* restart the authentication process */
        ntlm_request->auth_state = AUTHENTICATE_STATE_NONE;
        assert(ntlm_request->authserver ? ntlm_request->authserver == lastserver : 1);
        ntlm_request->authserver = NULL;
    }

    r->handler(r->data, NULL);
    cbdataReferenceDone(r->data);
    authenticateStateFree(r);
    debug(29, 9) ("NTLM HandleReply, telling stateful helper : %d\n", result);
    return result;
}

static void
authenticateNTLMStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "NTLM Authenticator Statistics:\n");
    helperStatefulStats(sentry, ntlmauthenticators);
}

/* is a particular challenge still valid ? */
static int
authenticateNTLMValidChallenge(ntlm_helper_state_t * helperstate)
{
    debug(29, 9) ("authenticateNTLMValidChallenge: Challenge is %s\n", helperstate->challenge ? "Valid" : "Invalid");

    if (helperstate->challenge == NULL)
        return 0;

    return 1;
}

/* does our policy call for changing the challenge now? */
static int
authenticateNTLMChangeChallenge_p(ntlm_helper_state_t * helperstate)
{
    /* don't check for invalid challenges just for expiry choices */
    /* this is needed because we have to starve the helper until all old
     * requests have been satisfied */

    if (!helperstate->renewed) {
        /* first use, no challenge has been set. Without this check, it will
         * loop forever */
        debug(29, 5) ("authenticateNTLMChangeChallenge_p: first use\n");
        return 0;
    }

    if (helperstate->challengeuses > ntlmConfig.challengeuses) {
        debug(29, 4) ("authenticateNTLMChangeChallenge_p: Challenge uses (%d) exceeded max uses (%d)\n", helperstate->challengeuses, ntlmConfig.challengeuses);
        return 1;
    }

    if (helperstate->renewed + ntlmConfig.challengelifetime < squid_curtime) {
        debug(29, 4) ("authenticateNTLMChangeChallenge_p: Challenge exceeded max lifetime by %d seconds\n", (int) (squid_curtime - (helperstate->renewed + ntlmConfig.challengelifetime)));
        return 1;
    }

    debug(29, 9) ("Challenge is to be reused\n");
    return 0;
}

/* send the initial data to a stateful ntlm authenticator module */
void
AuthNTLMUserRequest::module_start(RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    helper_stateful_server *server;
    ntlm_helper_state_t *helperstate;
    char buf[8192];
    char *sent_string = NULL;
    ntlm_user_t *ntlm_user;
    auth_user_t *auth_user;

    auth_user = this->user();
    ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
    assert(ntlm_user);
    assert(data);
    assert(auth_user->auth_type == AUTH_NTLM);
    debug(29, 9) ("authenticateNTLMStart: auth state '%d'\n", auth_state);

    switch (auth_state) {

    case AUTHENTICATE_STATE_NEGOTIATE:
        sent_string = ntlmnegotiate;
        break;

    case AUTHENTICATE_STATE_RESPONSE:
        sent_string = ntlmauthenticate;
        assert(authserver);
        debug(29, 9) ("authenticateNTLMStart: Asking NTLMauthenticator '%p'.\n", authserver);
        break;

    default:
        fatal("Invalid authenticate state for NTLMStart");
    }

    while (xisgraph(*sent_string))	/*trim NTLM */
        sent_string++;

    while (xisspace(*sent_string))	/*trim leading spaces */
        sent_string++;

    debug(29, 9) ("authenticateNTLMStart: state '%d'\n", auth_state);

    debug(29, 9) ("authenticateNTLMStart: '%s'\n", sent_string);

    if (ntlmConfig.authenticate == NULL) {
        debug(29, 0) ("authenticateNTLMStart: no NTLM program specified:'%s'\n", sent_string);
        handler(data, NULL);
        return;
    }

    /* this is ugly TODO: move the challenge generation routines to their own function and
     * tidy the logic up to make use of the efficiency we now have */
    switch (auth_state) {

    case AUTHENTICATE_STATE_NEGOTIATE:
        /*
         * 1: get a helper server
         * 2: does it have a challenge?
         * 3: tell it to get a challenge, or give ntlmauthdone the challenge
         */
        server = helperStatefulDefer(ntlmauthenticators);
        helperstate = server ? static_cast<ntlm_helper_state_t *>(helperStatefulServerGetData(server)) : NULL;

        while ((server != NULL) && authenticateNTLMChangeChallenge_p(helperstate)) {
            /* flag this helper for challenge changing */
            helperstate->starve = 1;
            /* and release the deferred request */
            helperStatefulReleaseServer(server);
            /* Get another deferrable server */
            server = helperStatefulDefer(ntlmauthenticators);
            helperstate = server ? static_cast<ntlm_helper_state_t *>(helperStatefulServerGetData(server)) : NULL;
        }

        if (server == NULL)
            debug(29, 9) ("unable to get a deferred ntlm helper... all helpers are refreshing challenges. Queuing as a placeholder request.\n");

        authserver = server;

        /* tell the log what helper we have been given */
        debug(29, 9) ("authenticateNTLMStart: helper '%p' assigned\n", server);

        /* server and valid challenge? */
        if ((server == NULL) || !authenticateNTLMValidChallenge(helperstate)) {
            /* No server, or server with invalid challenge */
            r = cbdataAlloc(authenticateStateData);
            r->handler = handler;
            r->data = cbdataReference(data);
            r->auth_user_request = this;

            lock()

                ; /* locking myself */

            if (server == NULL) {
                helperStatefulSubmit(ntlmauthenticators, NULL, authenticateNTLMHandleplaceholder, r, NULL);
            } else {
                /* Server with invalid challenge */
                snprintf(buf, 8192, "YR\n");
                helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, authserver);
            }
        } else {
            /* (server != NULL and we have a valid challenge) */
            /* TODO: turn the below into a function and call from here and handlereply */
            /* increment the challenge uses */
            helperstate->challengeuses++;
            /* assign the challenge */
            authchallenge = xstrdup(helperstate->challenge);
            /* we're not actually submitting a request, so we need to release the helper
             * should the connection close unexpectedly
             */
            authserver_deferred = 1;
            handler(data, NULL);
        }

        break;

    case AUTHENTICATE_STATE_RESPONSE:
        r = cbdataAlloc(authenticateStateData);
        r->handler = handler;
        r->data = cbdataReference(data);
        r->auth_user_request = this;

        lock()

            ;
        snprintf(buf, 8192, "KK %s\n", sent_string);

        /* getting rid of deferred request status */
        authserver_deferred = 0;

        helperStatefulSubmit(ntlmauthenticators, buf, authenticateNTLMHandleReply, r, authserver);

        debug(29, 9) ("authenticateNTLMstart: finished\n");

        break;

    default:
        fatal("Invalid authenticate state for NTLMStart");
    }
}

/* callback used by stateful helper routines */
static int
authenticateNTLMHelperServerAvailable(void *data)
{
    ntlm_helper_state_t *statedata = static_cast<ntlm_helper_state_t *>(data);

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

static void
authenticateNTLMHelperServerOnEmpty(void *data)
{
    ntlm_helper_state_t *statedata = static_cast<ntlm_helper_state_t *>(data);

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
static void
authenticateNTLMReleaseServer(auth_user_request_t * auth_user_request)
{
    AuthNTLMUserRequest *ntlm_request;
    assert(auth_user_request->user()->auth_type == AUTH_NTLM);
    ntlm_request = dynamic_cast< AuthNTLMUserRequest *>(auth_user_request);
    assert (ntlm_request);
    debug(29, 9) ("authenticateNTLMReleaseServer: releasing server '%p'\n", ntlm_request->authserver);
    helperStatefulReleaseServer(ntlm_request->authserver);
    ntlm_request->authserver = NULL;
}

/* clear any connection related authentication details */
void
AuthNTLMUserRequest::onConnectionClose(ConnStateData *conn)
{
    assert(conn != NULL);

    if (conn->auth_user_request != NULL) {
        assert (conn->auth_user_request == this);
        assert(this->conn == conn);

        if (authserver != NULL && authserver_deferred)
            authenticateNTLMReleaseServer(this);

        /* unlock the connection based lock */
        debug(29, 9) ("authenticateNTLMOnCloseConnection: Unlocking auth_user from the connection.\n");

        /* This still breaks the abstraction, but is at least read only now.
        * If needed, this could be ignored, as the conn deletion will also unlock
        * the auth user request.
        */
        this->unlock();

        conn->auth_user_request = NULL;
    }
}

/* NTLMLastHeader: return a pointer to the last header used in authenticating
 * the request/conneciton
 */
const char *
AuthNTLMUserRequest::connLastHeader()
{
    return ntlmauthenticate;
}

/*
 * Decode an NTLM [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
AuthUserRequest *
AuthNTLMConfig::decode(char const *proxy_auth)
{
    NTLMUser *newUser = new NTLMUser(&ntlmConfig);
    AuthNTLMUserRequest *auth_user_request = new AuthNTLMUserRequest ();
    assert(auth_user_request->user() == NULL);
    auth_user_request->user(newUser);
    auth_user_request->user()->auth_type = AUTH_NTLM;
    auth_user_request->user()->addRequest(auth_user_request);

    /* all we have to do is identify that it's NTLM - the helper does the rest */
    debug(29, 9) ("authenticateDecodeNTLMAuth: NTLM authentication\n");
    return auth_user_request;
}

static int
authenticateNTLMcmpUsername(ntlm_user_t * u1, ntlm_user_t * u2)
{
    return strcmp(u1->username(), u2->username());
}


/* there is a known race where a single client recieves the same challenge
 * and sends the same response to squid on a single select cycle.
 * Check for this and if found ignore the new link 
 */
static void
authenticateProxyAuthCacheAddLink(const char *key, auth_user_t * auth_user)
{

    struct ProxyAuthCachePointer *proxy_auth_hash;
    dlink_node *node;
    ntlm_user_t *ntlm_user;
    ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
    node = ntlm_user->proxy_auth_list.head;
    /* prevent duplicates */

    while (node) {

        if (!strcmp(key, (char const *)((struct ProxyAuthCachePointer *) node->data)->key))
            return;

        node = node->next;
    }

    proxy_auth_hash = static_cast<ProxyAuthCachePointer *>(ntlm_user_hash_pool->alloc());
    proxy_auth_hash->key = xstrdup(key);
    proxy_auth_hash->auth_user = auth_user;
    dlinkAddTail(proxy_auth_hash, &proxy_auth_hash->link, &ntlm_user->proxy_auth_list);
    hash_join(proxy_auth_cache, (hash_link *) proxy_auth_hash);
}

int
AuthNTLMUserRequest::authenticated() const
{
    if (auth_state == AUTHENTICATE_STATE_DONE)
        return 1;

    debug(29, 9) ("User not fully authenticated.\n");

    return 0;
}

void
AuthNTLMUserRequest::authenticate(HttpRequest * request, ConnStateData::Pointer conn, http_hdr_type type)
{
    const char *proxy_auth;

    struct ProxyAuthCachePointer *proxy_auth_hash = NULL;
    auth_user_hash_pointer *usernamehash;
    /* TODO: rename this!! */
    auth_user_t *auth_user;
    AuthNTLMUserRequest *ntlm_request;
    ntlm_user_t *ntlm_user;
    LOCAL_ARRAY(char, ntlmhash, NTLM_CHALLENGE_SZ * 2);
    /* get header */
    proxy_auth = httpHeaderGetStr(&request->header, type);

    auth_user = user();
    assert(auth_user);
    assert(auth_user->auth_type == AUTH_NTLM);
    ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
    ntlm_request = this;
    assert (ntlm_request);
    /* Check that we are in the client side, where we can generate
     * auth challenges */

    if (conn.getRaw() == NULL) {
        ntlm_request->auth_state = AUTHENTICATE_STATE_FAILED;
        debug(29, 1) ("authenticateNTLMAuthenticateUser: attempt to perform authentication without a connection!\n");
        return;
    }

    switch (ntlm_request->auth_state) {

    case AUTHENTICATE_STATE_NONE:
        /* we've recieved a negotiate request. pass to a helper */
        debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state ntlm none. %s\n", proxy_auth);
        ntlm_request->auth_state = AUTHENTICATE_STATE_NEGOTIATE;
        ntlm_request->ntlmnegotiate = xstrdup(proxy_auth);
        conn->auth_type = AUTH_NTLM;
        conn->auth_user_request = this;
        ntlm_request->conn = conn;
        /* and lock for the connection duration */
        debug(29, 9) ("authenticateNTLMAuthenticateUser: Locking auth_user from the connection.\n");

        this->lock()

        ;
        return;

        break;

    case AUTHENTICATE_STATE_NEGOTIATE:
        ntlm_request->auth_state = AUTHENTICATE_STATE_CHALLENGE;

        /* We _MUST_ have the auth challenge by now */
        assert(ntlm_request->authchallenge);

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

        proxy_auth_hash = static_cast<ProxyAuthCachePointer *>(hash_lookup(proxy_auth_cache, ntlmhash));

        if (!proxy_auth_hash) {	/* not in the hash table */
            debug(29, 4) ("authenticateNTLMAuthenticateUser: proxy-auth cache miss.\n");
            ntlm_request->auth_state = AUTHENTICATE_STATE_RESPONSE;
            /* verify with the ntlm helper */
        } else {
            debug(29, 4) ("authenticateNTLMAuthenticateUser: ntlm proxy-auth cache hit\n");
            /* throw away the temporary entry */
            ntlm_request->authserver_deferred = 0;
            authenticateNTLMReleaseServer(this);
            authenticateAuthUserMerge(auth_user, proxy_auth_hash->auth_user);
            auth_user = proxy_auth_hash->auth_user;
            this->user(auth_user);
            ntlm_request->auth_state = AUTHENTICATE_STATE_DONE;
            /* we found one */
            debug(29, 9) ("found matching cache entry\n");
            assert(auth_user->auth_type == AUTH_NTLM);
            /* get the existing entries details */
            ntlm_user = dynamic_cast<ntlm_user_t *>(auth_user);
            debug(29, 9) ("Username to be used is %s\n", ntlm_user->username());
            /* on ntlm auth we do not unlock the auth_user until the
             * connection is dropped. Thank MS for this quirk */
            auth_user->expiretime = current_time.tv_sec;
        }

        return;
        break;

    case AUTHENTICATE_STATE_RESPONSE:
        /* auth-challenge pair cache miss. We've just got the response from the helper */
        /*add to cache and let them through */
        ntlm_request->auth_state = AUTHENTICATE_STATE_DONE;
        /* this connection is authenticated */
        debug(29, 4) ("authenticated\nch    %s\nauth     %s\nauthuser %s\n",
                      ntlm_request->authchallenge,
                      ntlm_request->ntlmauthenticate,
                      ntlm_user->username());
        /* cache entries have authenticateauthheaderchallengestring */
        snprintf(ntlmhash, sizeof(ntlmhash) - 1, "%s%s",
                 ntlm_request->ntlmauthenticate,
                 ntlm_request->authchallenge);
        /* see if this is an existing user with a different proxy_auth
         * string */

        if ((usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, ntlm_user->username())))
           ) {
            while ((usernamehash->user()->auth_type != auth_user->auth_type) && (usernamehash->next) && !authenticateNTLMcmpUsername(dynamic_cast<ntlm_user_t *>(usernamehash->user()), ntlm_user)
                  )
                usernamehash = static_cast<AuthUserHashPointer*>(usernamehash->next);
            if (usernamehash->user()->auth_type == auth_user->auth_type) {
                /*
                 * add another link from the new proxy_auth to the
                 * auth_user structure and update the information */
                assert(proxy_auth_hash == NULL);
                authenticateProxyAuthCacheAddLink(ntlmhash, usernamehash->user());
                /* we can't seamlessly recheck the username due to the
                 * challenge nature of the protocol. Just free the 
                 * temporary auth_user */
                authenticateAuthUserMerge(auth_user, usernamehash->user());
                auth_user = usernamehash->user();
                this->user(auth_user);
            }
        } else {
            /* store user in hash's */
            auth_user->addToNameCache();
            authenticateProxyAuthCacheAddLink(ntlmhash, auth_user);
        }

        /* set these to now because this is either a new login from an
         * existing user or a new user */
        auth_user->expiretime = current_time.tv_sec;
        return;
        break;

    case AUTHENTICATE_STATE_DONE:
        fatal("authenticateNTLMAuthenticateUser: unexpect auth state DONE! Report a bug to the squid developers.\n");
        break;

    case AUTHENTICATE_STATE_FAILED:
        /* we've failed somewhere in authentication */
        debug(29, 9) ("authenticateNTLMAuthenticateUser: auth state ntlm failed. %s\n", proxy_auth);
        return;
    }

    return;
}

AuthNTLMUserRequest::AuthNTLMUserRequest() : ntlmnegotiate(NULL), authchallenge(NULL), ntlmauthenticate(NULL),
        authserver(NULL), auth_state(AUTHENTICATE_STATE_NONE),
        authserver_deferred(0), conn(NULL), _theUser(NULL)
{}

AuthNTLMUserRequest::~AuthNTLMUserRequest()
{
    if (ntlmnegotiate)
        xfree(ntlmnegotiate);

    if (authchallenge)
        xfree(authchallenge);

    if (ntlmauthenticate)
        xfree(ntlmauthenticate);

    if (authserver != NULL && authserver_deferred) {
        debug(29, 9) ("authenticateNTLMRequestFree: releasing server '%p'\n", authserver);
        helperStatefulReleaseServer(authserver);
        authserver = NULL;
    }
}

void
NTLMUser::deleteSelf() const
{
    delete this;
}

NTLMUser::NTLMUser (AuthConfig *config) : AuthUser (config)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
}

AuthConfig *
ntlmScheme::createConfig()
{
    return &ntlmConfig;
}

