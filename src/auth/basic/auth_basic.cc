/*
 * $Id: auth_basic.cc,v 1.27 2003/07/14 14:16:21 robertc Exp $
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
#include "auth_basic.h"
#include "authenticate.h"
#include "Store.h"
#include "HttpReply.h"

static void
authenticateStateFree(AuthenticateStateData * r)
{
    cbdataFree(r);
}

/* Basic Scheme */

static HLPCB authenticateBasicHandleReply;
static AUTHSACTIVE authenticateBasicActive;
static AUTHSAUTHED authenticateBasicAuthenticated;
static AUTHSAUTHUSER authenticateBasicAuthenticateUser;
static AUTHSCONFIGURED authBasicConfigured;
static AUTHSDIRECTION authenticateBasicDirection;
static AUTHSDECODE authenticateBasicDecodeAuth;
static AUTHSDUMP authBasicCfgDump;
static AUTHSFIXERR authenticateBasicFixErrorHeader;
static AUTHSFREE authenticateBasicFreeUser;
static AUTHSFREECONFIG authBasicFreeConfig;
static AUTHSPARSE authBasicParse;
static AUTHSINIT authBasicInit;
static AUTHSSTART authenticateBasicStart;
static AUTHSSTATS authenticateBasicStats;
static AUTHSUSERNAME authenticateBasicUsername;
static AUTHSSHUTDOWN authBasicDone;

static helper *basicauthenticators = NULL;

static auth_basic_config *basicConfig = NULL;

static int authbasic_initialised = 0;
MemPool *basic_data_pool = NULL;


/*
 *
 * Public Functions
 *
 */

AUTHSSETUP authSchemeSetup_basic;

void
authSchemeSetup_basic(authscheme_entry_t * authscheme)
{
    assert(!authbasic_initialised);
    authscheme->Active = authenticateBasicActive;
    authscheme->parse = authBasicParse;
    authscheme->dump = authBasicCfgDump;
    authscheme->init = authBasicInit;
    authscheme->authAuthenticate = authenticateBasicAuthenticateUser;
    authscheme->authenticated = authenticateBasicAuthenticated;
    authscheme->configured = authBasicConfigured;
    authscheme->authFixHeader = authenticateBasicFixErrorHeader;
    authscheme->FreeUser = authenticateBasicFreeUser;
    authscheme->freeconfig = authBasicFreeConfig;
    authscheme->authStart = authenticateBasicStart;
    authscheme->authStats = authenticateBasicStats;
    authscheme->authUserUsername = authenticateBasicUsername;
    authscheme->getdirection = authenticateBasicDirection;
    authscheme->oncloseconnection = NULL;
    authscheme->decodeauth = authenticateBasicDecodeAuth;
    authscheme->donefunc = authBasicDone;
    authscheme->authConnLastHeader = NULL;
}

/* internal functions */

static void
authBasicDone(void)
{
    if (basicauthenticators)
        helperShutdown(basicauthenticators);

    authbasic_initialised = 0;

    if (!shutting_down)
        return;

    if (basicauthenticators)
        helperFree(basicauthenticators);

    basicauthenticators = NULL;

#if DEBUGSHUTDOWN

    if (basic_data_pool) {
        memPoolDestroy(&basic_data_pool);
        basic_data_pool = NULL;
    }

#endif
    debug(29, 2) ("authBasicDone: Basic authentication Shutdown.\n");
}

static int
authenticateBasicActive()
{
    return (authbasic_initialised == 1) ? 1 : 0;
}

static int
authBasicConfigured()
{
    if ((basicConfig != NULL) && (basicConfig->authenticate != NULL) &&
            (basicConfig->authenticateChildren != 0) &&
            (basicConfig->basicAuthRealm != NULL)) {
        debug(29, 9) ("authBasicConfigured: returning configured\n");
        return 1;
    }

    debug(29, 9) ("authBasicConfigured: returning unconfigured\n");
    return 0;
}

static int
authenticateBasicAuthenticated(auth_user_request_t * auth_user_request)
{
    basic_data *basic_auth = static_cast<basic_data *>(auth_user_request->auth_user->scheme_data);

    if ((basic_auth->flags.credentials_ok == 1) && (basic_auth->credentials_checkedtime + basicConfig->credentialsTTL > squid_curtime))
        return 1;

    debug(29, 4) ("User not authenticated or credentials need rechecking.\n");

    return 0;
}

#if UNUSED_CODE
static int
authenticateBasiccmpUsername(basic_data * u1, basic_data * u2)
{
    return strcmp(u1->username, u2->username);
}

#endif

/* log a basic user in
 */
static void
authenticateBasicAuthenticateUser(auth_user_request_t * auth_user_request, request_t * request, ConnStateData::Pointer conn, http_hdr_type type)
{
    auth_user_t *auth_user;
    basic_data *basic_auth;

    assert(auth_user_request->auth_user != NULL);
    auth_user = auth_user_request->auth_user;

    assert(auth_user->scheme_data != NULL);
    basic_auth = static_cast<basic_data *>(auth_user->scheme_data);

    /* if the password is not ok, do an identity */

    if (basic_auth->flags.credentials_ok != 1)
        return;

    /* are we about to recheck the credentials externally? */
    if ((basic_auth->credentials_checkedtime + basicConfig->credentialsTTL) <= squid_curtime) {
        debug(29, 4) ("authBasicAuthenticate: credentials expired - rechecking\n");
        return;
    }

    /* we have been through the external helper, and the credentials haven't expired */
    debug(29, 9) ("authenticateBasicAuthenticateuser: user '%s' authenticated\n",
                  basic_auth->username);

    /* Decode now takes care of finding the auth_user struct in the cache */
    /* after external auth occurs anyway */
    auth_user->expiretime = current_time.tv_sec;

    return;
}

int
authenticateBasicDirection(auth_user_request_t * auth_user_request)
{
    /* null auth_user is checked for by authenticateDirection */
    auth_user_t *auth_user = auth_user_request->auth_user;
    basic_data *basic_auth = static_cast<basic_data *>(auth_user->scheme_data);

    switch (basic_auth->flags.credentials_ok) {

    case 0:			/* not checked */
        return -1;

    case 1:			/* checked & ok */

        if (basic_auth->credentials_checkedtime + basicConfig->credentialsTTL <= squid_curtime)
            return -1;

        return 0;

    case 2:			/* paused while waiting for a username:password check on another request */
        return -1;

    case 3:			/* authentication process failed. */
        return -2;
    }

    return -2;
}

void
authenticateBasicFixErrorHeader(auth_user_request_t * auth_user_request, HttpReply * rep, http_hdr_type type, request_t * request)
{
    if (basicConfig->authenticate) {
        debug(29, 9) ("authenticateFixErrorHeader: Sending type:%d header: 'Basic realm=\"%s\"'\n", type, basicConfig->basicAuthRealm);
        httpHeaderPutStrf(&rep->header, type, "Basic realm=\"%s\"", basicConfig->basicAuthRealm);
    }
}

/* free any allocated configuration details */
void
authBasicFreeConfig(authScheme * scheme)
{
    if (basicConfig == NULL)
        return;

    assert(basicConfig == scheme->scheme_data);

    if (basicConfig->authenticate)
        wordlistDestroy(&basicConfig->authenticate);

    if (basicConfig->basicAuthRealm)
        safe_free(basicConfig->basicAuthRealm);

    xfree(basicConfig);

    basicConfig = NULL;
}

void
authenticateBasicFreeUser(auth_user_t * auth_user)
{
    basic_data *basic_auth = static_cast<basic_data *>(auth_user->scheme_data);
    debug(29, 5) ("authenticateBasicFreeUser: Clearing Basic scheme data\n");

    if (basic_auth->username)
        xfree(basic_auth->username);

    if (basic_auth->passwd)
        xfree(basic_auth->passwd);

    memPoolFree(basic_data_pool, auth_user->scheme_data);

    auth_user->scheme_data = NULL;
}

static void
authenticateBasicHandleReply(void *data, char *reply)
{
    AuthenticateStateData *r = static_cast<AuthenticateStateData *>(data);
    auth_user_t *auth_user;
    basic_data *basic_auth;
    BasicAuthQueueNode *tmpnode;
    char *t = NULL;
    void *cbdata;
    debug(29, 9) ("authenticateBasicHandleReply: {%s}\n", reply ? reply : "<NULL>");

    if (reply) {
        if ((t = strchr(reply, ' ')))
            *t = '\0';

        if (*reply == '\0')
            reply = NULL;
    }

    assert(r->auth_user_request != NULL);
    assert(r->auth_user_request->auth_user->auth_type == AUTH_BASIC);
    auth_user = r->auth_user_request->auth_user;
    basic_auth = static_cast<basic_data *>(auth_user->scheme_data);

    if (reply && (strncasecmp(reply, "OK", 2) == 0))
        basic_auth->flags.credentials_ok = 1;
    else
        basic_auth->flags.credentials_ok = 3;

    basic_auth->credentials_checkedtime = squid_curtime;

    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata, NULL);

    cbdataReferenceDone(r->data);

    while (basic_auth->auth_queue) {
        tmpnode = basic_auth->auth_queue->next;

        if (cbdataReferenceValidDone(basic_auth->auth_queue->data, &cbdata))
            basic_auth->auth_queue->handler(cbdata, NULL);

        xfree(basic_auth->auth_queue);

        basic_auth->auth_queue = tmpnode;
    }

    authenticateStateFree(r);
}

static void
authBasicCfgDump(StoreEntry * entry, const char *name, authScheme * scheme)
{
    auth_basic_config *config = static_cast<auth_basic_config *>(scheme->scheme_data);
    wordlist *list = config->authenticate;
    storeAppendPrintf(entry, "%s %s", name, "basic");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n");

    storeAppendPrintf(entry, "%s basic realm %s\n", name, config->basicAuthRealm);
    storeAppendPrintf(entry, "%s basic children %d\n", name, config->authenticateChildren);
    storeAppendPrintf(entry, "%s basic concurrency %d\n", name, config->authenticateConcurrency);
    storeAppendPrintf(entry, "%s basic credentialsttl %d seconds\n", name, (int) config->credentialsTTL);

}

static void
authBasicParse(authScheme * scheme, int n_configured, char *param_str)
{
    if (scheme->scheme_data == NULL) {
        assert(basicConfig == NULL);
        /* this is the first param to be found */
        scheme->scheme_data = xmalloc(sizeof(auth_basic_config));
        memset(scheme->scheme_data, 0, sizeof(auth_basic_config));
        basicConfig = static_cast<auth_basic_config *>(scheme->scheme_data);
        basicConfig->authenticateChildren = 5;
        basicConfig->credentialsTTL = 2 * 60 * 60;	/* two hours */
    }

    basicConfig =  static_cast<auth_basic_config *>(scheme->scheme_data);

    if (strcasecmp(param_str, "program") == 0) {
        if (basicConfig->authenticate)
            wordlistDestroy(&basicConfig->authenticate);

        parse_wordlist(&basicConfig->authenticate);

        requirePathnameExists("authparam basic program", basicConfig->authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        parse_int(&basicConfig->authenticateChildren);
    } else if (strcasecmp(param_str, "concurrency") == 0) {
        parse_int(&basicConfig->authenticateConcurrency);
    } else if (strcasecmp(param_str, "realm") == 0) {
        parse_eol(&basicConfig->basicAuthRealm);
    } else if (strcasecmp(param_str, "credentialsttl") == 0) {
        parse_time_t(&basicConfig->credentialsTTL);
    } else {
        debug(28, 0) ("unrecognised basic auth scheme parameter '%s'\n", param_str);
    }
}

static void
authenticateBasicStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Basic Authenticator Statistics:\n");
    helperStats(sentry, basicauthenticators);
}

CBDATA_TYPE(AuthenticateStateData);

/* authenticateBasicUsername: return a pointer to the username in the */
char const *
authenticateBasicUsername(auth_user_t const * auth_user)
{
    basic_data *basic_auth =  static_cast<basic_data *>(auth_user->scheme_data);

    if (basic_auth)
        return basic_auth->username;

    return NULL;
}

static basic_data *
authBasicDataNew(void)
{
    basic_data *temp;
    temp =  static_cast<basic_data *>(memPoolAlloc(basic_data_pool));
    assert(temp != NULL);
    temp->username = NULL;
    temp->passwd = NULL;
    temp->auth_queue = NULL;
    return temp;
}

#if UNUSED_CODE
static void
authBasicDataFree(basic_data * basic_auth)
{}

#endif

static auth_user_t *
authBasicAuthUserFindUsername(const char *username)
{
    AuthUserHashPointer *usernamehash;
    debug(29, 9) ("authBasicAuthUserFindUsername: Looking for user '%s'\n", username);

    if (username && (usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, username)))) {
        while (usernamehash) {
            if ((authUserHashPointerUser(usernamehash)->auth_type == AUTH_BASIC) &&
                    !strcmp(username, (char const *)usernamehash->key))
                return authUserHashPointerUser(usernamehash);

            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        }
    }

    return NULL;
}



/*
 * Decode a Basic [Proxy-]Auth string, linking the passed auth_user_request structure 
 * to any existing user structure or creating one if needed. Note that just returning
 * will be treated as "cannot decode credentials". Use the message field to return a 
 * descriptive message to the user.
 */

static void
authenticateBasicDecodeAuth(auth_user_request_t * auth_user_request, const char *proxy_auth)
{
    char *sent_auth;
    char *cleartext;
    basic_data *basic_auth, local_basic;
    auth_user_t *auth_user;
    dlink_node *node;

    /* decode the username */
    /* trim BASIC from string */

    while (!xisspace(*proxy_auth))
        proxy_auth++;

    local_basic.passwd = NULL;

    /* Trim leading whitespace before decoding */
    while (xisspace(*proxy_auth))
        proxy_auth++;

    /* username and password */
    sent_auth = xstrdup(proxy_auth);

    /* Trim trailing \n before decoding */
    strtok(sent_auth, "\n");

    cleartext = uudecode(sent_auth);

    xfree(sent_auth);

    /*
     * Don't allow NL or CR in the credentials.
     * Oezguer Kesim <oec@codeblau.de>
     */
    strtok(cleartext, "\r\n");

    debug(29, 9) ("authenticateBasicDecodeAuth: cleartext = '%s'\n", cleartext);

    local_basic.username = xstrndup(cleartext, USER_IDENT_SZ);

    xfree(cleartext);

    if ((cleartext = strchr(local_basic.username, ':')) != NULL)
        *(cleartext)++ = '\0';

    local_basic.passwd = cleartext;

    if (cleartext == NULL) {
        debug(29, 4) ("authenticateBasicDecodeAuth: no password in proxy authorization header '%s'\n",
                      proxy_auth);
        local_basic.passwd = NULL;
        authenticateSetDenyMessage (auth_user_request, "no password was present in the HTTP [proxy-]authorization header. This is most likely a browser bug");
    } else if (*cleartext == '\0') {
        debug(29, 4) ("authenticateBasicDecodeAuth: Disallowing empty password,"
                      "user is '%s'\n", local_basic.username);
        local_basic.passwd = NULL;
        authenticateSetDenyMessage (auth_user_request, "Request denied because you provided an empty password. Users MUST have a password.");
    }

    /* special case: we have to free the strings for user and password
     * if we are not returning a filled out structure 
     */
    if (local_basic.passwd == NULL) {
        if (local_basic.username) {
            /* log the username */
            debug(29, 9) ("authBasicDecodeAuth: Creating new user for logging '%s'\n", local_basic.username);
            /* new auth_user */
            auth_user = authenticateAuthUserNew("basic");
            /* new scheme data */
            basic_auth = authBasicDataNew();
            /* save the credentials */
            basic_auth->username = local_basic.username;
            /* link the scheme data in */
            auth_user->scheme_data = basic_auth;
            /* set the auth_user type */
            auth_user->auth_type = AUTH_BROKEN;
            /* link the request to the user */
            auth_user_request->auth_user = auth_user;
            /* lock for the auth_user_request link */
            authenticateAuthUserLock(auth_user);
            node = dlinkNodeNew();
            dlinkAdd(auth_user_request, node, &auth_user->requests);
        }

        return;
    } else {
        local_basic.passwd = xstrndup(cleartext, USER_IDENT_SZ);
    }

    /* now lookup and see if we have a matching auth_user structure in memory. */

    if ((auth_user = authBasicAuthUserFindUsername(local_basic.username)) == NULL) {
        /* the user doesn't exist in the username cache yet */
        debug(29, 9) ("authBasicDecodeAuth: Creating new user '%s'\n", local_basic.username);
        /* new auth_user */
        auth_user = authenticateAuthUserNew("basic");
        /* new scheme data */
        basic_auth = authBasicDataNew();
        /* save the credentials */
        basic_auth->username = local_basic.username;
        basic_auth->passwd = local_basic.passwd;
        /* link the scheme data in */
        auth_user->scheme_data = basic_auth;
        /* set the auth_user type */
        auth_user->auth_type = AUTH_BASIC;
        /* current time for timeouts */
        auth_user->expiretime = current_time.tv_sec;

        /* this auth_user struct is the 'lucky one' to get added to the username cache */
        /* the requests after this link to the auth_user */
        /* store user in hash */
        authenticateUserNameCacheAdd(auth_user);
    } else {
        debug(29, 9) ("authBasicDecodeAuth: Found user '%s' in the user cache as '%p'\n", local_basic.username, auth_user);
        xfree(local_basic.username);
        basic_auth =  static_cast<basic_data *>(auth_user->scheme_data);

        if (strcmp(local_basic.passwd, basic_auth->passwd)) {
            debug(29, 4) ("authBasicDecodeAuth: new password found. Updating in user master record and resetting auth state to unchecked\n");
            basic_auth->flags.credentials_ok = 0;
            xfree(basic_auth->passwd);
            basic_auth->passwd = local_basic.passwd;
        } else
            xfree(local_basic.passwd);

        if (basic_auth->flags.credentials_ok == 3) {
            debug(29, 4) ("authBasicDecodeAuth: last attempt to authenticate this user failed, resetting auth state to unchecked\n");
            basic_auth->flags.credentials_ok = 0;
        }
    }

    /* link the request to the user */
    auth_user_request->auth_user = auth_user;

    /* lock for the auth_user_request link */
    authenticateAuthUserLock(auth_user);

    node = dlinkNodeNew();

    dlinkAdd(auth_user_request, node, &auth_user->requests);

    return;
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
static void
authBasicInit(authScheme * scheme)
{
    static int init = 0;

    if (basicConfig->authenticate) {
        if (!basic_data_pool)
            basic_data_pool = memPoolCreate("Basic Scheme User Data", sizeof(basic_data));

        authbasic_initialised = 1;

        if (basicauthenticators == NULL)
            basicauthenticators = helperCreate("basicauthenticator");

        basicauthenticators->cmdline = basicConfig->authenticate;

        basicauthenticators->n_to_start = basicConfig->authenticateChildren;

        basicauthenticators->concurrency = basicConfig->authenticateConcurrency;

        basicauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(basicauthenticators);

        if (!init) {
            cachemgrRegister("basicauthenticator",
                             "Basic User Authenticator Stats",
                             authenticateBasicStats, 0, 1);
            init++;
        }

        CBDATA_INIT_TYPE(AuthenticateStateData);
    }
}

/* send the initial data to a basic authenticator module */
static void
authenticateBasicStart(auth_user_request_t * auth_user_request, RH * handler, void *data)
{
    AuthenticateStateData *r = NULL;
    char buf[8192];
    char user[1024], pass[1024];
    basic_data *basic_auth;
    assert(auth_user_request);
    assert(handler);
    assert(auth_user_request->auth_user->auth_type == AUTH_BASIC);
    assert(auth_user_request->auth_user->scheme_data != NULL);
    basic_auth = static_cast<basic_data *>(auth_user_request->auth_user->scheme_data);
    debug(29, 9) ("authenticateStart: '%s:%s'\n", basic_auth->username,
                  basic_auth->passwd);

    if (basicConfig->authenticate == NULL) {
        handler(data, NULL);
        return;
    }

    /* check to see if the auth_user already has a request outstanding */
    if (basic_auth->flags.credentials_ok == 2) {
        /* there is a request with the same credentials already being verified */
        BasicAuthQueueNode *node;
        node = static_cast<BasicAuthQueueNode *>(xmalloc(sizeof(BasicAuthQueueNode)));
        assert(node);
        /* save the details */
        node->next = basic_auth->auth_queue;
        basic_auth->auth_queue = node;
        node->auth_user_request = auth_user_request;
        node->handler = handler;
        node->data = cbdataReference(data);
        return;
    } else {
        r = cbdataAlloc(AuthenticateStateData);
        r->handler = handler;
        r->data = cbdataReference(data);
        r->auth_user_request = auth_user_request;
        /* mark the user as haveing verification in progress */
        basic_auth->flags.credentials_ok = 2;
        xstrncpy(user, rfc1738_escape(basic_auth->username), sizeof(user));
        xstrncpy(pass, rfc1738_escape(basic_auth->passwd), sizeof(pass));
        snprintf(buf, sizeof(buf), "%s %s\n", user, pass);
        helperSubmit(basicauthenticators, buf, authenticateBasicHandleReply, r);
    }
}
