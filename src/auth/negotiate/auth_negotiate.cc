
/*
 * $Id: auth_negotiate.cc,v 1.11 2006/09/03 04:12:01 hno Exp $
 *
 * DEBUG: section 29    Negotiate Authenticator
 * AUTHOR: Robert Collins, Henrik Nordstrom, Francesco Chemolli
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
#include "auth_negotiate.h"
#include "authenticate.h"
#include "CacheManager.h"
#include "Store.h"
#include "client_side.h"
#include "HttpReply.h"
#include "HttpRequest.h"
/* TODO remove this include */
#include "negotiateScheme.h"
#include "wordlist.h"

static void
authenticateNegotiateReleaseServer(auth_user_request_t * auth_user_request);


static void
authenticateStateFree(authenticateStateData * r)
{
    cbdataFree(r);
}

/* Negotiate Scheme */
static HLPSCB authenticateNegotiateHandleReply;
static AUTHSSTATS authenticateNegotiateStats;

static statefulhelper *negotiateauthenticators = NULL;

CBDATA_TYPE(authenticateStateData);

static int authnegotiate_initialised = 0;

static auth_negotiate_config negotiateConfig;

static hash_table *proxy_auth_cache = NULL;

/*
 *
 * Private Functions
 *
 */

/* move to negotiateScheme.cc */
void
negotiateScheme::done()
{
    /* TODO: this should be a Config call. */
    debug(29, 2) ("negotiateScheme::done: shutting down Negotiate authentication.\n");

    if (negotiateauthenticators)
        helperStatefulShutdown(negotiateauthenticators);

    authnegotiate_initialised = 0;

    if (!shutting_down)
        return;

    if (negotiateauthenticators)
        helperStatefulFree(negotiateauthenticators);

    negotiateauthenticators = NULL;

    debug(29, 2) ("negotiateScheme::done: Negotiate authentication Shutdown.\n");
}

/* free any allocated configuration details */
void
AuthNegotiateConfig::done()
{
    if (authenticate)
        wordlistDestroy(&authenticate);
}

void
AuthNegotiateConfig::dump(StoreEntry * entry, const char *name, AuthConfig * scheme)
{
    wordlist *list = authenticate;
    storeAppendPrintf(entry, "%s %s", name, "negotiate");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n%s negotiate children %d\n",
                      name, authenticateChildren);
    storeAppendPrintf(entry, "%s %s keep_alive %s\n", name, "negotiate", keep_alive ? "on" : "off");

}

AuthNegotiateConfig::AuthNegotiateConfig() : authenticateChildren(5), keep_alive(1)
{ }

void
AuthNegotiateConfig::parse(AuthConfig * scheme, int n_configured, char *param_str)
{
    if (strcasecmp(param_str, "program") == 0) {
        if (authenticate)
            wordlistDestroy(&authenticate);

        parse_wordlist(&authenticate);

        requirePathnameExists("authparam negotiate program", authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        parse_int(&authenticateChildren);
    } else if (strcasecmp(param_str, "keep_alive") == 0) {
        parse_onoff(&keep_alive);
    } else {
        debug(29, 0) ("AuthNegotiateConfig::parse: unrecognised negotiate auth scheme parameter '%s'\n", param_str);
    }

    /*
     * disable client side request pipelining. There is a race with
     * Negotiate when the client sends a second request on an Negotiate
     * connection before the authenticate challenge is sent. With
     * this patch, the client may fail to authenticate, but squid's
     * state will be preserved.  Caveats: this should be a post-parse
     * test, but that can wait for the modular parser to be integrated.
     */
    if (authenticate)
        Config.onoff.pipeline_prefetch = 0;
}

const char *
AuthNegotiateConfig::type() const
{
    return negotiateScheme::GetInstance().type();
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
AuthNegotiateConfig::init(AuthConfig * scheme)
{
    if (authenticate) {
        authnegotiate_initialised = 1;

        if (negotiateauthenticators == NULL)
            negotiateauthenticators = helperStatefulCreate("negotiateauthenticator");

        if (!proxy_auth_cache)
            proxy_auth_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);

        assert(proxy_auth_cache);

        negotiateauthenticators->cmdline = authenticate;

        negotiateauthenticators->n_to_start = authenticateChildren;

        negotiateauthenticators->ipc_type = IPC_STREAM;

        helperStatefulOpenServers(negotiateauthenticators);

        CBDATA_INIT_TYPE(authenticateStateData);
    }
}

void
AuthNegotiateConfig::registerWithCacheManager(CacheManager & manager)
{
    manager.registerAction("negotiateauthenticator",
                           "Negotiate User Authenticator Stats",
                           authenticateNegotiateStats, 0, 1);
}

bool
AuthNegotiateConfig::active() const
{
    return authnegotiate_initialised == 1;
}

bool
AuthNegotiateConfig::configured() const
{
    if ((authenticate != NULL) && (authenticateChildren != 0)) {
        debug(29, 9) ("AuthNegotiateConfig::configured: returning configured\n");
        return true;
    }

    debug(29, 9) ("AuthNegotiateConfig::configured: returning unconfigured\n");
    return false;
}

/* Negotiate Scheme */
/* See AuthUserRequest.cc::authenticateDirection for return values */
int
AuthNegotiateUserRequest::module_direction()
{
    /* null auth_user is checked for by authenticateDirection */

    if (waiting || client_blob)
        return -1; /* need helper response to continue */

    switch (auth_state) {

        /* no progress at all. */

    case AUTHENTICATE_STATE_NONE:
        debug(29, 1) ("AuthNegotiateUserRequest::direction: called before Negotiate Authenticate for request %p!. Report a bug to squid-dev.\n",this);
        return -2; /* error */

    case AUTHENTICATE_STATE_FAILED:
        return -2; /* error */


    case AUTHENTICATE_STATE_IN_PROGRESS:
        assert(server_blob);
        return 1; /* send to client */

    case AUTHENTICATE_STATE_FINISHED:
        return 0; /* do nothing */

    case AUTHENTICATE_STATE_DONE:
        return 0; /* do nothing */

    case AUTHENTICATE_STATE_INITIAL:
        debug(29, 1) ("AuthNegotiateUserRequest::direction: Unexpected AUTHENTICATE_STATE_INITIAL\n");
        return -2;
    }

    return -2;
}

/* add the [proxy]authorisation header */
void
AuthNegotiateUserRequest::addHeader(HttpReply * rep, int accel)
{
    http_hdr_type type;

    if (!server_blob)
        return;

    /* don't add to authentication error pages */

    if ((!accel && rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (accel && rep->sline.status == HTTP_UNAUTHORIZED))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

    httpHeaderPutStrf(&rep->header, type, "Negotiate %s", server_blob);

    safe_free(server_blob);
}

void
AuthNegotiateConfig::fixHeader(auth_user_request_t *auth_user_request, HttpReply *rep, http_hdr_type type, HttpRequest * request)
{
    AuthNegotiateUserRequest *negotiate_request;

    if (!request->flags.proxy_keepalive)
        return;

    if (!authenticate)
        return;

    /* New request, no user details */
    if (auth_user_request == NULL) {
        debug(29, 9) ("AuthNegotiateConfig::fixHeader: Sending type:%d header: 'NEGOTIATE'\n", type);
        httpHeaderPutStrf(&rep->header, type, "NEGOTIATE");

        if (!keep_alive) {
            /* drop the connection */
            rep->header.delByName("keep-alive");
            request->flags.proxy_keepalive = 0;
        }
    } else {
        negotiate_request = dynamic_cast<AuthNegotiateUserRequest *>(auth_user_request);

        switch (negotiate_request->auth_state) {

        case AUTHENTICATE_STATE_FAILED:
            /* here it makes sense to drop the connection, as auth is
             * tied to it, even if MAYBE the client could handle it - Kinkie */
            rep->header.delByName("keep-alive");
            request->flags.proxy_keepalive = 0;
            /* fall through */

        case AUTHENTICATE_STATE_FINISHED:
            /* Special case: authentication finished OK but disallowed by ACL.
             * Need to start over to give the client another chance.
             */

            if (negotiate_request->server_blob) {
                debug(29, 9) ("authenticateNegotiateFixErrorHeader: Sending type:%d header: 'Negotiate %s'\n", type, negotiate_request->server_blob);
                httpHeaderPutStrf(&rep->header, type, "Negotiate %s", negotiate_request->server_blob);
                safe_free(negotiate_request->server_blob);
            } else {
                debug(29, 9) ("authenticateNegotiateFixErrorHeader: Connection authenticated\n");
                httpHeaderPutStrf(&rep->header, type, "Negotiate");
            }

            break;

        case AUTHENTICATE_STATE_NONE:
            /* semantic change: do not drop the connection.
             * 2.5 implementation used to keep it open - Kinkie */
            debug(29, 9) ("AuthNegotiateConfig::fixHeader: Sending type:%d header: 'NEGOTIATE'\n", type);
            httpHeaderPutStrf(&rep->header, type, "Negotiate");
            break;

        case AUTHENTICATE_STATE_IN_PROGRESS:
            /* we're waiting for a response from the client. Pass it the blob */
            debug(29, 9) ("AuthNegotiateConfig::fixHeader: Sending type:%d header: 'Negotiate %s'\n", type, negotiate_request->server_blob);
            httpHeaderPutStrf(&rep->header, type, "Negotiate %s", negotiate_request->server_blob);
            request->flags.must_keepalive = 1;
            safe_free(negotiate_request->server_blob);
            break;


        default:
            debug(29, 0) ("AuthNegotiateConfig::fixHeader: state %d.\n", negotiate_request->auth_state);
            fatal("unexpected state in AuthenticateNegotiateFixErrorHeader.\n");
        }
    }
}

NegotiateUser::~NegotiateUser()
{
    debug(29, 5) ("NegotiateUser::~NegotiateUser: doing nothing to clearNEGOTIATE scheme data for '%p'\n",this);
}

static stateful_helper_callback_t
authenticateNegotiateHandleReply(void *data, void *lastserver, char *reply)
{
    authenticateStateData *r = static_cast<authenticateStateData *>(data);

    int valid;
    stateful_helper_callback_t result = S_HELPER_UNKNOWN;
    char *blob, *arg = NULL;

    auth_user_request_t *auth_user_request;
    AuthUser *auth_user;
    NegotiateUser *negotiate_user;
    AuthNegotiateUserRequest *negotiate_request;

    debug(29, 8) ("authenticateNegotiateHandleReply: helper: '%p' sent us '%s'\n", lastserver, reply ? reply : "<NULL>");
    valid = cbdataReferenceValid(r->data);

    if (!valid) {
        debug(29, 1) ("authenticateNegotiateHandleReply: invalid callback data. Releasing helper '%p'.\n", lastserver);
        cbdataReferenceDone(r->data);
        authenticateStateFree(r);
        debug(29, 9) ("authenticateNegotiateHandleReply: telling stateful helper : %d\n", S_HELPER_RELEASE);
        return S_HELPER_RELEASE;
    }

    if (!reply) {
        debug(29, 1) ("authenticateNegotiateHandleReply: Helper '%p' crashed!.\n", lastserver);
        reply = (char *)"BH Internal error";
    }

    auth_user_request = r->auth_user_request;
    assert(auth_user_request != NULL);
    negotiate_request = dynamic_cast<AuthNegotiateUserRequest *>(auth_user_request);

    assert(negotiate_request->waiting);
    negotiate_request->waiting = 0;
    safe_free(negotiate_request->client_blob);

    auth_user = negotiate_request->user();
    assert(auth_user != NULL);
    assert(auth_user->auth_type == AUTH_NEGOTIATE);
    negotiate_user = dynamic_cast<negotiate_user_t *>(auth_user_request->user());

    if (negotiate_request->authserver == NULL)
        negotiate_request->authserver = static_cast<helper_stateful_server*>(lastserver);
    else
        assert(negotiate_request->authserver == lastserver);

    /* seperate out the useful data */
    blob = strchr(reply, ' ');

    if (blob) {
        blob++;
        arg = strchr(blob + 1, ' ');
    } else {
        arg = NULL;
    }

    if (strncasecmp(reply, "TT ", 3) == 0) {
        /* we have been given a blob to send to the client */

        if (arg)
            *arg++ = '\0';

        safe_free(negotiate_request->server_blob);

        negotiate_request->server_blob = xstrdup(blob);

        negotiate_request->auth_state = AUTHENTICATE_STATE_IN_PROGRESS;

        auth_user_request->denyMessage("Authentication in progress");

        debug(29, 4) ("authenticateNegotiateHandleReply: Need to challenge the client with a server blob '%s'\n", blob);

        result = S_HELPER_RESERVE;
    } else if (strncasecmp(reply, "AF ", 3) == 0 && arg != NULL) {
        /* we're finished, release the helper */

        if (arg)
            *arg++ = '\0';

        negotiate_user->username(arg);

        auth_user_request->denyMessage("Login successful");

        safe_free(negotiate_request->server_blob);

        negotiate_request->server_blob = xstrdup(blob);

        authenticateNegotiateReleaseServer(negotiate_request);

        negotiate_request->auth_state = AUTHENTICATE_STATE_FINISHED;

        result = S_HELPER_RELEASE;

        debug(29, 4) ("authenticateNegotiateHandleReply: Successfully validated user via NEGOTIATE. Username '%s'\n", blob);
    } else if (strncasecmp(reply, "NA ", 3) == 0 && arg != NULL) {
        /* authentication failure (wrong password, etc.) */

        if (arg)
            *arg++ = '\0';

        auth_user_request->denyMessage(arg);

        negotiate_request->auth_state = AUTHENTICATE_STATE_FAILED;

        safe_free(negotiate_request->server_blob);

        negotiate_request->server_blob = xstrdup(blob);

        authenticateNegotiateReleaseServer(negotiate_request);

        result = S_HELPER_RELEASE;

        debug(29, 4) ("authenticateNegotiateHandleReply: Failed validating user via NEGOTIATE. Error returned '%s'\n", blob);
    } else if (strncasecmp(reply, "BH ", 3) == 0) {
        /* TODO kick off a refresh process. This can occur after a YR or after
         * a KK. If after a YR release the helper and resubmit the request via
         * Authenticate NEGOTIATE start.
         * If after a KK deny the user's request w/ 407 and mark the helper as
         * Needing YR. */
        auth_user_request->denyMessage(blob);
        negotiate_request->auth_state = AUTHENTICATE_STATE_FAILED;
        safe_free(negotiate_request->server_blob);
        authenticateNegotiateReleaseServer(negotiate_request);
        result = S_HELPER_RELEASE;
        debug(29, 1) ("authenticateNegotiateHandleReply: Error validating user via NEGOTIATE. Error returned '%s'\n", reply);
    } else {
        /* protocol error */
        fatalf("authenticateNegotiateHandleReply: *** Unsupported helper response ***, '%s'\n", reply);
    }

    r->handler(r->data, NULL);
    cbdataReferenceDone(r->data);
    authenticateStateFree(r);
    debug(29, 9) ("authenticateNegotiateHandleReply: telling stateful helper : %d\n", result);
    return result;
}

static void
authenticateNegotiateStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "NEGOTIATE Authenticator Statistics:\n");
    helperStatefulStats(sentry, negotiateauthenticators);
}


/* send the initial data to a stateful negotiate authenticator module */
void
AuthNegotiateUserRequest::module_start(RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    static char buf[8192];
    negotiate_user_t *negotiate_user;
    auth_user_t *auth_user = user();

    assert(data);
    assert(handler);
    assert(auth_user);
    assert(auth_user->auth_type == AUTH_NEGOTIATE);

    negotiate_user = dynamic_cast<negotiate_user_t *>(user());

    debug(29, 8) ("AuthNegotiateUserRequest::module_start: auth state is '%d'\n", auth_state);

    if (negotiateConfig.authenticate == NULL) {
        debug(29, 0) ("AuthNegotiateUserRequest::module_start: no NEGOTIATE program specified.");
        handler(data, NULL);
        return;
    }

    r = cbdataAlloc(authenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = this;

    lock()

        ;
    if (auth_state == AUTHENTICATE_STATE_INITIAL) {
        snprintf(buf, 8192, "YR %s\n", client_blob); //CHECKME: can ever client_blob be 0 here?
    } else {
        snprintf(buf, 8192, "KK %s\n", client_blob);
    }

    waiting = 1;

    safe_free(client_blob);
    helperStatefulSubmit(negotiateauthenticators, buf, authenticateNegotiateHandleReply, r, authserver);
}

/* clear the NEGOTIATE helper of being reserved for future requests */
static void
authenticateNegotiateReleaseServer(auth_user_request_t * auth_user_request)
{
    AuthNegotiateUserRequest *negotiate_request;
    assert(auth_user_request->user()->auth_type == AUTH_NEGOTIATE);
    negotiate_request = dynamic_cast< AuthNegotiateUserRequest *>(auth_user_request);
    debug(29, 9) ("authenticateNegotiateReleaseServer: releasing server '%p'\n", negotiate_request->authserver);
    /* is it possible for the server to be NULL? hno seems to think so.
     * Let's see what happens, might segfault in helperStatefulReleaseServer
     * if it does. I leave it like this not to cover possibly problematic
     * code-paths. Kinkie */
    helperStatefulReleaseServer(negotiate_request->authserver);
    negotiate_request->authserver = NULL;
}

/* clear any connection related authentication details */
void
AuthNegotiateUserRequest::onConnectionClose(ConnStateData *connection)
{
    assert(connection != NULL);

    debug(29,8)("AuthNegotiateUserRequest::onConnectionClose: closing connection '%p' (this is '%p')\n",connection,this);

    if (connection->auth_user_request == NULL) {
        debug(29,8)("AuthNegotiateUserRequest::onConnectionClose: no auth_user_request\n");
        return;
    }

    if (authserver != NULL)
        authenticateNegotiateReleaseServer(this);

    /* unlock the connection based lock */
    debug(29, 9) ("AuthNegotiateUserRequest::onConnectionClose: Unlocking auth_user from the connection '%p'.\n",connection);

    /* This still breaks the abstraction, but is at least read only now.
    * If needed, this could be ignored, as the conn deletion will also unlock
    * the auth user request.
    */
    unlock();

    connection->auth_user_request = NULL;
}

/*
 * Decode a NEGOTIATE [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
AuthUserRequest *
AuthNegotiateConfig::decode(char const *proxy_auth)
{
    NegotiateUser *newUser = new NegotiateUser(&negotiateConfig);
    AuthNegotiateUserRequest *auth_user_request = new AuthNegotiateUserRequest ();
    assert(auth_user_request->user() == NULL);
    auth_user_request->user(newUser);
    auth_user_request->user()->auth_type = AUTH_NEGOTIATE;
    auth_user_request->user()->addRequest(auth_user_request);

    /* all we have to do is identify that it's NEGOTIATE - the helper does the rest */
    debug(29, 9) ("AuthNegotiateConfig::decode: NEGOTIATE authentication\n");
    return auth_user_request;
}

int
AuthNegotiateUserRequest::authenticated() const
{
    if (auth_state == AUTHENTICATE_STATE_FINISHED) {
        debug(29, 9) ("AuthNegotiateUserRequest::authenticated: user authenticated.\n");
        return 1;
    }

    debug(29, 9) ("AuthNegotiateUserRequest::authenticated: user not fully authenticated.\n");

    return 0;
}

void
AuthNegotiateUserRequest::authenticate(HttpRequest * request, ConnStateData::Pointer conn, http_hdr_type type)
{
    const char *proxy_auth, *blob;

    //ProxyAuthCachePointer *proxy_auth_hash = NULL;
    auth_user_hash_pointer *usernamehash;

    /* TODO: rename this!! */
    auth_user_t *local_auth_user;
    negotiate_user_t *negotiate_user;

    local_auth_user = user();
    assert(local_auth_user);
    assert(local_auth_user->auth_type == AUTH_NEGOTIATE);
    negotiate_user = dynamic_cast<negotiate_user_t *>(local_auth_user);
    assert (this);

    /* Check that we are in the client side, where we can generate
     * auth challenges */

    if (conn.getRaw() == NULL) {
        auth_state = AUTHENTICATE_STATE_FAILED;
        debug(29, 1) ("AuthNegotiateUserRequest::authenticate: attempt to perform authentication without a connection!\n");
        return;
    }

    if (waiting) {
        debug(29, 1) ("AuthNegotiateUserRequest::authenticate: waiting for helper reply!\n");
        return;
    }

    if (server_blob) {
        debug(29,2)("AuthNegotiateUserRequest::authenticate: need to challenge client '%s'!\n", server_blob);
        return;
    }

    /* get header */
    proxy_auth = request->header.getStr(type);

    /* locate second word */
    blob = proxy_auth;

    while (xisspace(*blob) && *blob)
        blob++;

    while (!xisspace(*blob) && *blob)
        blob++;

    while (xisspace(*blob) && *blob)
        blob++;

    switch (auth_state) {

    case AUTHENTICATE_STATE_NONE:
        /* we've recieved a negotiate request. pass to a helper */
        debug(29, 9) ("AuthNegotiateUserRequest::authenticate: auth state negotiate none. Received blob: '%s'\n", proxy_auth);
        auth_state = AUTHENTICATE_STATE_INITIAL;
        safe_free(client_blob);
        client_blob=xstrdup(blob);
        conn->auth_type = AUTH_NEGOTIATE;
        conn->auth_user_request = this;
        conn = conn;

        lock()

            ;
        return;

        break;

    case AUTHENTICATE_STATE_INITIAL:
        debug(29,1)("AuthNegotiateUserRequest::authenticate: need to ask helper\n");

        return;

        break;


    case AUTHENTICATE_STATE_IN_PROGRESS:
        /* we should have received a blob from the client. Hand it off to
         * some helper */
        safe_free(client_blob);

        client_blob = xstrdup (blob);

        return;

        break;

    case AUTHENTICATE_STATE_FINISHED:
        /* connection is authenticated */
        debug(29, 4) ("AuthNegotiateUserRequest::authenticate: authenticated user %s\n", negotiate_user->username());

        /* see if this is an existing user with a different proxy_auth
         * string */
        usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, negotiate_user->username()));

        while (usernamehash && (usernamehash->user()->auth_type != AUTH_NEGOTIATE || strcmp(usernamehash->user()->username(), negotiate_user->username()) != 0))
            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);

        if (usernamehash) {
            /* we can't seamlessly recheck the username due to the
             * challenge-response nature of the protocol.
             * Just free the temporary auth_user */
            usernamehash->user()->absorb(local_auth_user);
            //authenticateAuthUserMerge(local_auth_user, usernamehash->user());
            local_auth_user = usernamehash->user();
            _auth_user = local_auth_user;
        } else {
            /* store user in hash's */
            local_auth_user->addToNameCache();
            // authenticateUserNameCacheAdd(local_auth_user);
        }

        /* set these to now because this is either a new login from an
         * existing user or a new user */
        local_auth_user->expiretime = current_time.tv_sec;

        authenticateNegotiateReleaseServer(this);

        auth_state = AUTHENTICATE_STATE_DONE;

        return;

        break;

    case AUTHENTICATE_STATE_DONE:
        fatal("AuthNegotiateUserRequest::authenticate: unexpect auth state DONE! Report a bug to the squid developers.\n");

        break;

    case AUTHENTICATE_STATE_FAILED:
        /* we've failed somewhere in authentication */
        debug(29, 9) ("AuthNegotiateUserRequest::authenticate: auth state negotiate failed. %s\n", proxy_auth);

        return;

        break;
    }

    return;
}

AuthNegotiateUserRequest::AuthNegotiateUserRequest() :
        conn(NULL), auth_state(AUTHENTICATE_STATE_NONE),
        _theUser(NULL)
{
    waiting=0;
    client_blob=0;
    server_blob=0;
    authserver=NULL;
}

AuthNegotiateUserRequest::~AuthNegotiateUserRequest()
{
    safe_free(server_blob);
    safe_free(client_blob);

    if (authserver != NULL) {
        debug(29, 9) ("AuthNegotiateUserRequest::~AuthNegotiateUserRequest: releasing server '%p'\n", authserver);
        helperStatefulReleaseServer(authserver);
        authserver = NULL;
    }
}

void
NegotiateUser::deleteSelf() const
{
    delete this;
}

NegotiateUser::NegotiateUser (AuthConfig *config) : AuthUser (config)
{
    proxy_auth_list.head = proxy_auth_list.tail = NULL;
}

AuthConfig *
negotiateScheme::createConfig()
{
    return &negotiateConfig;
}

const char *
AuthNegotiateUserRequest::connLastHeader()
{
    return NULL;
}

