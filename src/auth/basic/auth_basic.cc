/*
 * $Id$
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
#include "auth/Gadgets.h"
#include "CacheManager.h"
#include "Store.h"
#include "HttpReply.h"
#include "basicScheme.h"
#include "rfc1738.h"
#include "wordlist.h"
#include "SquidTime.h"

static void
authenticateStateFree(AuthenticateStateData * r)
{
    cbdataFree(r);
}

/* Basic Scheme */

static HLPCB authenticateBasicHandleReply;
static AUTHSSTATS authenticateBasicStats;

static helper *basicauthenticators = NULL;

static AuthBasicConfig basicConfig;

static int authbasic_initialised = 0;


/*
 *
 * Public Functions
 *
 */

/* internal functions */

/* TODO: move to basicScheme.cc - after all per request and user functions are moved out */
void
basicScheme::done()
{
    /* TODO: this should be a Config call. */

    if (basicauthenticators)
        helperShutdown(basicauthenticators);

    authbasic_initialised = 0;

    if (!shutting_down)
        return;

    if (basicauthenticators)
        helperFree(basicauthenticators);

    basicauthenticators = NULL;

    /* XXX Reinstate auth shutdown for dynamic schemes? */
    debugs(29, DBG_CRITICAL, HERE << "Basic authentication Shutdown.");
}

bool
AuthBasicConfig::active() const
{
    return authbasic_initialised == 1;
}

bool
AuthBasicConfig::configured() const
{
    if ((authenticate != NULL) && (authenticateChildren != 0) &&
            (basicAuthRealm != NULL)) {
        debugs(29, 9, HERE << "returning configured");
        return true;
    }

    debugs(29, 9, HERE << "returning unconfigured");
    return false;
}

const char *
AuthBasicConfig::type() const
{
    return basicScheme::GetInstance().type();
}

AuthBasicUserRequest::AuthBasicUserRequest() : _theUser(NULL)
{}

AuthBasicUserRequest::~AuthBasicUserRequest()
{}


bool
BasicUser::authenticated() const
{
    if ((flags.credentials_ok == 1) && (credentials_checkedtime + basicConfig.credentialsTTL > squid_curtime))
        return true;

    debugs(29, 4, "User not authenticated or credentials need rechecking.");

    return false;
}

int
AuthBasicUserRequest::authenticated() const
{
    BasicUser const *basic_auth = dynamic_cast<BasicUser const *>(user());

    if (basic_auth && basic_auth->authenticated())
        return 1;

    return 0;
}

/* log a basic user in
 */
void
AuthBasicUserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
{
    assert(user() != NULL);

    basic_data *basic_auth = dynamic_cast<BasicUser *>(user());

    /* if the password is not ok, do an identity */

    if (!basic_auth || basic_auth->flags.credentials_ok != 1)
        return;

    /* are we about to recheck the credentials externally? */
    if ((basic_auth->credentials_checkedtime + basicConfig.credentialsTTL) <= squid_curtime) {
        debugs(29, 4, "authBasicAuthenticate: credentials expired - rechecking");
        return;
    }

    /* we have been through the external helper, and the credentials haven't expired */
    debugs(29, 9, "authenticateBasicAuthenticateuser: user '" << basic_auth->username() << "' authenticated");

    /* Decode now takes care of finding the AuthUser struct in the cache */
    /* after external auth occurs anyway */
    basic_auth->expiretime = current_time.tv_sec;

    return;
}

int
AuthBasicUserRequest::module_direction()
{
    /* null auth_user is checked for by authenticateDirection */
    basic_data *basic_auth = dynamic_cast<BasicUser *>(user());
    assert (basic_auth);

    switch (basic_auth->flags.credentials_ok) {

    case 0:			/* not checked */
        return -1;

    case 1:			/* checked & ok */

        if (basic_auth->credentials_checkedtime + basicConfig.credentialsTTL <= squid_curtime)
            return -1;

        return 0;

    case 2:			/* paused while waiting for a username:password check on another request */
        return -1;

    case 3:			/* authentication process failed. */
        return 0;
    }

    return -2;
}

void
AuthBasicConfig::fixHeader(AuthUserRequest *auth_user_request, HttpReply *rep, http_hdr_type hdrType, HttpRequest * request)
{
    if (authenticate) {
        debugs(29, 9, HERE << "Sending type:" << hdrType << " header: 'Basic realm=\"" << basicAuthRealm << "\"'");
        httpHeaderPutStrf(&rep->header, hdrType, "Basic realm=\"%s\"", basicAuthRealm);
    }
}

/* free any allocated configuration details */
void
AuthBasicConfig::done()
{
    if (authenticate)
        wordlistDestroy(&authenticate);

    if (basicAuthRealm)
        safe_free(basicAuthRealm);
}

BasicUser::~BasicUser()
{
    safe_free(passwd);
    safe_free(cleartext);
}

static void
authenticateBasicHandleReply(void *data, char *reply)
{
    AuthenticateStateData *r = static_cast<AuthenticateStateData *>(data);
    BasicAuthQueueNode *tmpnode;
    char *t = NULL;
    void *cbdata;
    debugs(29, 9, HERE << "{" << (reply ? reply : "<NULL>") << "}");

    if (reply) {
        if ((t = strchr(reply, ' ')))
            *t++ = '\0';

        if (*reply == '\0')
            reply = NULL;
    }

    assert(r->auth_user_request != NULL);
    assert(r->auth_user_request->user()->auth_type == AUTH_BASIC);
    basic_data *basic_auth = dynamic_cast<basic_data *>(r->auth_user_request->user());

    assert(basic_auth != NULL);

    if (reply && (strncasecmp(reply, "OK", 2) == 0))
        basic_auth->flags.credentials_ok = 1;
    else {
        basic_auth->flags.credentials_ok = 3;

        if (t && *t)
            r->auth_user_request->setDenyMessage(t);
    }

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

void
AuthBasicConfig::dump(StoreEntry * entry, const char *name, AuthConfig * scheme)
{
    wordlist *list = authenticate;
    storeAppendPrintf(entry, "%s %s", name, "basic");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n");

    storeAppendPrintf(entry, "%s basic realm %s\n", name, basicAuthRealm);
    storeAppendPrintf(entry, "%s basic children %d\n", name, authenticateChildren);
    storeAppendPrintf(entry, "%s basic concurrency %d\n", name, authenticateConcurrency);
    storeAppendPrintf(entry, "%s basic credentialsttl %d seconds\n", name, (int) credentialsTTL);
    storeAppendPrintf(entry, "%s basic casesensitive %s\n", name, casesensitive ? "on" : "off");
}

AuthBasicConfig::AuthBasicConfig()
{
    /* TODO: move into initialisation list */
    authenticateChildren = 5;
    credentialsTTL = 2 * 60 * 60;	/* two hours */
    basicAuthRealm = xstrdup("Squid proxy-caching web server");
}

AuthBasicConfig::~AuthBasicConfig()
{
    safe_free(basicAuthRealm);
}

void
AuthBasicConfig::parse(AuthConfig * scheme, int n_configured, char *param_str)
{
    if (strcasecmp(param_str, "program") == 0) {
        if (authenticate)
            wordlistDestroy(&authenticate);

        parse_wordlist(&authenticate);

        requirePathnameExists("auth_param basic program", authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        parse_int(&authenticateChildren);
    } else if (strcasecmp(param_str, "concurrency") == 0) {
        parse_int(&authenticateConcurrency);
    } else if (strcasecmp(param_str, "realm") == 0) {
        parse_eol(&basicAuthRealm);
    } else if (strcasecmp(param_str, "credentialsttl") == 0) {
        parse_time_t(&credentialsTTL);
    } else if (strcasecmp(param_str, "casesensitive") == 0) {
        parse_onoff(&casesensitive);
    } else if (strcasecmp(param_str, "utf8") == 0) {
        parse_onoff(&utf8);
    } else {
        debugs(29, DBG_CRITICAL, HERE << "unrecognised basic auth scheme parameter '" << param_str << "'");
    }
}

static void
authenticateBasicStats(StoreEntry * sentry)
{
    helperStats(sentry, basicauthenticators, "Basic Authenticator Statistics");
}

CBDATA_TYPE(AuthenticateStateData);

static AuthUser *
authBasicAuthUserFindUsername(const char *username)
{
    AuthUserHashPointer *usernamehash;
    debugs(29, 9, HERE << "Looking for user '" << username << "'");

    if (username && (usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, username)))) {
        while (usernamehash) {
            if ((usernamehash->user()->auth_type == AUTH_BASIC) &&
                    !strcmp(username, (char const *)usernamehash->key))
                return usernamehash->user();

            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        }
    }

    return NULL;
}

void
BasicUser::deleteSelf() const
{
    delete this;
}

BasicUser::BasicUser(AuthConfig *aConfig) : AuthUser (aConfig) , passwd (NULL), credentials_checkedtime(0), auth_queue(NULL), cleartext (NULL), currentRequest (NULL), httpAuthHeader (NULL)
{
    flags.credentials_ok = 0;
}

bool
BasicUser::decodeCleartext()
{
    char *sent_auth = NULL;

    /* username and password */
    sent_auth = xstrdup(httpAuthHeader);

    /* Trim trailing \n before decoding */
    strtok(sent_auth, "\n");

    cleartext = uudecode(sent_auth);

    safe_free(sent_auth);

    if (!cleartext)
        return false;

    /*
     * Don't allow NL or CR in the credentials.
     * Oezguer Kesim <oec@codeblau.de>
     */
    debugs(29, 9, HERE << "'" << cleartext << "'");

    if (strcspn(cleartext, "\r\n") != strlen(cleartext)) {
        debugs(29, 1, HERE << "bad characters in authorization header '" << httpAuthHeader << "'");
        safe_free(cleartext);
        return false;
    }
    return true;
}

void
BasicUser::extractUsername()
{
    char * seperator = strchr(cleartext, ':');

    if (seperator == NULL) {
        username(cleartext);
    } else {
        /* terminate the username */
        *seperator = '\0';

        username(cleartext);

        /* replace the colon so we can find the password */
        *seperator = ':';
    }

    if (!basicConfig.casesensitive)
        Tolower((char *)username());
}

void
BasicUser::extractPassword()
{
    passwd = strchr(cleartext, ':');

    if (passwd == NULL) {
        debugs(29, 4, HERE << "no password in proxy authorization header '" << httpAuthHeader << "'");
        passwd = NULL;
        currentRequest->setDenyMessage("no password was present in the HTTP [proxy-]authorization header. This is most likely a browser bug");
    } else {
        ++passwd;
        if (*passwd == '\0') {
            debugs(29, 4, HERE << "Disallowing empty password,user is '" << username() << "'");
            passwd = NULL;
            currentRequest->setDenyMessage("Request denied because you provided an empty password. Users MUST have a password.");
        } else {
            passwd = xstrndup(passwd, USER_IDENT_SZ);
        }
    }
}

void
BasicUser::decode(char const *proxy_auth, AuthUserRequest *auth_user_request)
{
    currentRequest = auth_user_request;
    httpAuthHeader = proxy_auth;
    if (decodeCleartext ()) {
        extractUsername();
        extractPassword();
    }
    currentRequest = NULL;
    httpAuthHeader = NULL;
}

bool
BasicUser::valid() const
{
    if (username() == NULL)
        return false;
    if (passwd == NULL)
        return false;
    return true;
}

void
BasicUser::makeLoggingInstance(AuthBasicUserRequest *auth_user_request)
{
    if (username()) {
        /* log the username */
        debugs(29, 9, HERE << "Creating new user for logging '" << username() << "'");
        /* new scheme data */
        BasicUser *basic_auth = new BasicUser(& basicConfig);
        auth_user_request->user(basic_auth);
        /* save the credentials */
        basic_auth->username(username());
        username(NULL);
        /* set the auth_user type */
        basic_auth->auth_type = AUTH_BROKEN;
        /* link the request to the user */
        basic_auth->addRequest(auth_user_request);
    }
}

AuthUser *
BasicUser::makeCachedFrom()
{
    /* the user doesn't exist in the username cache yet */
    debugs(29, 9, HERE << "Creating new user '" << username() << "'");
    BasicUser *basic_user = new BasicUser(&basicConfig);
    /* save the credentials */
    basic_user->username(username());
    username(NULL);
    basic_user->passwd = passwd;
    passwd = NULL;
    /* set the auth_user type */
    basic_user->auth_type = AUTH_BASIC;
    /* current time for timeouts */
    basic_user->expiretime = current_time.tv_sec;

    /* this basic_user struct is the 'lucky one' to get added to the username cache */
    /* the requests after this link to the basic_user */
    /* store user in hash */
    basic_user->addToNameCache();
    return basic_user;
}

void
BasicUser::updateCached(BasicUser *from)
{
    debugs(29, 9, HERE << "Found user '" << from->username() << "' in the user cache as '" << this << "'");

    if (strcmp(from->passwd, passwd)) {
        debugs(29, 4, HERE << "new password found. Updating in user master record and resetting auth state to unchecked");
        flags.credentials_ok = 0;
        xfree(passwd);
        passwd = from->passwd;
        from->passwd = NULL;
    }

    if (flags.credentials_ok == 3) {
        debugs(29, 4, HERE << "last attempt to authenticate this user failed, resetting auth state to unchecked");
        flags.credentials_ok = 0;
    }
}

/**
 * Decode a Basic [Proxy-]Auth string, linking the passed
 * auth_user_request structure to any existing user structure or creating one
 * if needed. Note that just returning will be treated as
 * "cannot decode credentials". Use the message field to return a
 * descriptive message to the user.
 */
AuthUserRequest *
AuthBasicConfig::decode(char const *proxy_auth)
{
    AuthBasicUserRequest *auth_user_request = new AuthBasicUserRequest();
    /* decode the username */
    /* trim BASIC from string */

    while (xisgraph(*proxy_auth))
        proxy_auth++;

    BasicUser *basic_auth, local_basic(&basicConfig);

    /* Trim leading whitespace before decoding */
    while (xisspace(*proxy_auth))
        proxy_auth++;

    local_basic.decode(proxy_auth, auth_user_request);

    if (!local_basic.valid()) {
        local_basic.makeLoggingInstance(auth_user_request);
        return auth_user_request;
    }

    /* now lookup and see if we have a matching auth_user structure in
     * memory. */

    AuthUser *auth_user;

    if ((auth_user = authBasicAuthUserFindUsername(local_basic.username())) == NULL) {
        auth_user = local_basic.makeCachedFrom();
        basic_auth = dynamic_cast<BasicUser *>(auth_user);
        assert (basic_auth);
    } else {
        basic_auth = dynamic_cast<BasicUser *>(auth_user);
        assert (basic_auth);
        basic_auth->updateCached (&local_basic);
    }

    /* link the request to the in-cache user */
    auth_user_request->user(basic_auth);

    basic_auth->addRequest(auth_user_request);

    return auth_user_request;
}

/** Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
AuthBasicConfig::init(AuthConfig * scheme)
{
    if (authenticate) {
        authbasic_initialised = 1;

        if (basicauthenticators == NULL)
            basicauthenticators = helperCreate("basicauthenticator");

        basicauthenticators->cmdline = authenticate;

        basicauthenticators->n_to_start = authenticateChildren;

        basicauthenticators->concurrency = authenticateConcurrency;

        basicauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(basicauthenticators);

        CBDATA_INIT_TYPE(AuthenticateStateData);
    }
}

void
AuthBasicConfig::registerWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("basicauthenticator",
                   "Basic User Authenticator Stats",
                   authenticateBasicStats, 0, 1);
}

void
BasicUser::queueRequest(AuthUserRequest * auth_user_request, RH * handler, void *data)
{
    BasicAuthQueueNode *node;
    node = static_cast<BasicAuthQueueNode *>(xmalloc(sizeof(BasicAuthQueueNode)));
    assert(node);
    /* save the details */
    node->next = auth_queue;
    auth_queue = node;
    node->auth_user_request = auth_user_request;
    node->handler = handler;
    node->data = cbdataReference(data);
}

/* send the initial data to a basic authenticator module */
void
AuthBasicUserRequest::module_start(RH * handler, void *data)
{
    basic_data *basic_auth;
    assert(user()->auth_type == AUTH_BASIC);
    basic_auth = dynamic_cast<basic_data *>(user());
    assert(basic_auth != NULL);
    debugs(29, 9, HERE << "'" << basic_auth->username() << ":" << basic_auth->passwd << "'");

    if (basicConfig.authenticate == NULL) {
        handler(data, NULL);
        return;
    }

    /* check to see if the auth_user already has a request outstanding */
    if (basic_auth->flags.credentials_ok == 2) {
        /* there is a request with the same credentials already being verified */
        basic_auth->queueRequest(this, handler, data);
        return;
    }

    basic_auth->submitRequest (this, handler, data);
}

void
BasicUser::submitRequest(AuthUserRequest * auth_user_request, RH * handler, void *data)
{
    /* mark the user as haveing verification in progress */
    flags.credentials_ok = 2;
    AuthenticateStateData *r = NULL;
    char buf[8192];
    char user[1024], pass[1024];
    r = cbdataAlloc(AuthenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = auth_user_request;
    if (basicConfig.utf8) {
        latin1_to_utf8(user, sizeof(user), username());
        latin1_to_utf8(pass, sizeof(pass), passwd);
        xstrncpy(user, rfc1738_escape(user), sizeof(user));
        xstrncpy(pass, rfc1738_escape(pass), sizeof(pass));
    } else {
        xstrncpy(user, rfc1738_escape(username()), sizeof(user));
        xstrncpy(pass, rfc1738_escape(passwd), sizeof(pass));
    }
    snprintf(buf, sizeof(buf), "%s %s\n", user, pass);
    helperSubmit(basicauthenticators, buf, authenticateBasicHandleReply, r);
}

AuthConfig *
basicScheme::createConfig()
{
    return &basicConfig;
}
