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
#include "auth/basic/auth_basic.h"
#include "auth/basic/basicScheme.h"
#include "auth/basic/basicUserRequest.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "charset.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "HttpReply.h"
#include "rfc1738.h"
#include "uudecode.h"
#include "wordlist.h"
#include "SquidTime.h"

/* Basic Scheme */
static HLPCB authenticateBasicHandleReply;
static AUTHSSTATS authenticateBasicStats;

static helper *basicauthenticators = NULL;

static int authbasic_initialised = 0;


/*
 *
 * Public Functions
 *
 */

/* internal functions */

bool
AuthBasicConfig::active() const
{
    return authbasic_initialised == 1;
}

bool
AuthBasicConfig::configured() const
{
    if ((authenticateProgram != NULL) && (authenticateChildren.n_max != 0) &&
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
    return basicScheme::GetInstance()->type();
}

int32_t
BasicUser::ttl() const
{
    if (credentials() != Ok && credentials() != Pending)
        return -1; // TTL is obsolete NOW.

    int32_t basic_ttl = expiretime - squid_curtime + static_cast<AuthBasicConfig*>(config)->credentialsTTL;
    int32_t global_ttl = static_cast<int32_t>(expiretime - squid_curtime + Config.authenticateTTL);

    return min(basic_ttl, global_ttl);
}

bool
BasicUser::authenticated() const
{
    if ((credentials() == Ok) && (expiretime + static_cast<AuthBasicConfig*>(config)->credentialsTTL > squid_curtime))
        return true;

    debugs(29, 4, "User not authenticated or credentials need rechecking.");

    return false;
}

void
AuthBasicConfig::fixHeader(AuthUserRequest::Pointer auth_user_request, HttpReply *rep, http_hdr_type hdrType, HttpRequest * request)
{
    if (authenticateProgram) {
        debugs(29, 9, HERE << "Sending type:" << hdrType << " header: 'Basic realm=\"" << basicAuthRealm << "\"'");
        httpHeaderPutStrf(&rep->header, hdrType, "Basic realm=\"%s\"", basicAuthRealm);
    }
}

void
AuthBasicConfig::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (basicauthenticators) {
        helperShutdown(basicauthenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

/** shutdown the auth helpers and free any allocated configuration details */
void
AuthBasicConfig::done()
{
    authbasic_initialised = 0;

    if (basicauthenticators) {
        helperShutdown(basicauthenticators);
    }

    delete basicauthenticators;
    basicauthenticators = NULL;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);

    if (basicAuthRealm)
        safe_free(basicAuthRealm);
}

BasicUser::~BasicUser()
{
    safe_free(passwd);
}

static void
authenticateBasicHandleReply(void *data, char *reply)
{
    authenticateStateData *r = static_cast<authenticateStateData *>(data);
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

    /* this is okay since we only play with the BasicUser child fields below
     * and dont pass the pointer itself anywhere */
    BasicUser *basic_auth = dynamic_cast<BasicUser *>(r->auth_user_request->user().getRaw());

    assert(basic_auth != NULL);

    if (reply && (strncasecmp(reply, "OK", 2) == 0))
        basic_auth->credentials(AuthUser::Ok);
    else {
        basic_auth->credentials(AuthUser::Failed);

        if (t && *t)
            r->auth_user_request->setDenyMessage(t);
    }

    basic_auth->expiretime = squid_curtime;

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
    wordlist *list = authenticateProgram;
    storeAppendPrintf(entry, "%s %s", name, "basic");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n");

    storeAppendPrintf(entry, "%s basic realm %s\n", name, basicAuthRealm);
    storeAppendPrintf(entry, "%s basic children %d startup=%d idle=%d concurrency=%d\n", name, authenticateChildren.n_max, authenticateChildren.n_startup, authenticateChildren.n_idle, authenticateChildren.concurrency);
    storeAppendPrintf(entry, "%s basic credentialsttl %d seconds\n", name, (int) credentialsTTL);
    storeAppendPrintf(entry, "%s basic casesensitive %s\n", name, casesensitive ? "on" : "off");
}

AuthBasicConfig::AuthBasicConfig() :
        credentialsTTL( 2*60*60 ),
        casesensitive(0),
        utf8(0)
{
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
        if (authenticateProgram)
            wordlistDestroy(&authenticateProgram);

        parse_wordlist(&authenticateProgram);

        requirePathnameExists("auth_param basic program", authenticateProgram->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        authenticateChildren.parseConfig();
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

static AuthUser::Pointer
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

BasicUser::BasicUser(AuthConfig *aConfig) :
        AuthUser(aConfig),
        passwd(NULL),
        auth_queue(NULL),
        currentRequest(NULL)
{}

char *
AuthBasicConfig::decodeCleartext(const char *httpAuthHeader)
{
    const char *proxy_auth = httpAuthHeader;

    /* trim BASIC from string */
    while (xisgraph(*proxy_auth))
        proxy_auth++;

    /* Trim leading whitespace before decoding */
    while (xisspace(*proxy_auth))
        proxy_auth++;

    /* Trim trailing \n before decoding */
    // XXX: really? is the \n actually still there? does the header parse not drop it?
    char *eek = xstrdup(proxy_auth);
    strtok(eek, "\n");
    char *cleartext = uudecode(eek);
    safe_free(eek);

    if (cleartext) {
        /*
         * Don't allow NL or CR in the credentials.
         * Oezguer Kesim <oec@codeblau.de>
         */
        debugs(29, 9, HERE << "'" << cleartext << "'");

        if (strcspn(cleartext, "\r\n") != strlen(cleartext)) {
            debugs(29, DBG_IMPORTANT, "WARNING: Bad characters in authorization header '" << httpAuthHeader << "'");
            safe_free(cleartext);
        }
    }
    return cleartext;
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
BasicUser::updateCached(BasicUser *from)
{
    debugs(29, 9, HERE << "Found user '" << from->username() << "' already in the user cache as '" << this << "'");

    assert(strcmp(from->username(), username()) == 0);

    if (strcmp(from->passwd, passwd)) {
        debugs(29, 4, HERE << "new password found. Updating in user master record and resetting auth state to unchecked");
        credentials(Unchecked);
        xfree(passwd);
        passwd = from->passwd;
        from->passwd = NULL;
    }

    if (credentials() == Failed) {
        debugs(29, 4, HERE << "last attempt to authenticate this user failed, resetting auth state to unchecked");
        credentials(Unchecked);
    }
}

/**
 * Decode a Basic [Proxy-]Auth string, linking the passed
 * auth_user_request structure to any existing user structure or creating one
 * if needed. Note that just returning will be treated as
 * "cannot decode credentials". Use the message field to return a
 * descriptive message to the user.
 */
AuthUserRequest::Pointer
AuthBasicConfig::decode(char const *proxy_auth)
{
    AuthUserRequest::Pointer auth_user_request = dynamic_cast<AuthUserRequest*>(new AuthBasicUserRequest);
    /* decode the username */

    // retrieve the cleartext (in a dynamically allocated char*)
    char *cleartext = decodeCleartext(proxy_auth);

    // empty header? no auth details produced...
    if (!cleartext)
        return auth_user_request;

    AuthUser::Pointer lb;
    /* permitted because local_basic is purely local function scope. */
    BasicUser *local_basic = NULL;

    char *seperator = strchr(cleartext, ':');

    lb = local_basic = new BasicUser(this);
    if (seperator == NULL) {
        local_basic->username(cleartext);
    } else {
        /* terminate the username */
        *seperator = '\0';
        local_basic->username(cleartext);
        local_basic->passwd = xstrdup(seperator+1);
    }

    if (!casesensitive)
        Tolower((char *)local_basic->username());

    if (local_basic->passwd == NULL) {
        debugs(29, 4, HERE << "no password in proxy authorization header '" << proxy_auth << "'");
        auth_user_request->setDenyMessage("no password was present in the HTTP [proxy-]authorization header. This is most likely a browser bug");
    } else {
        if (local_basic->passwd[0] == '\0') {
            debugs(29, 4, HERE << "Disallowing empty password. User is '" << local_basic->username() << "'");
            safe_free(local_basic->passwd);
            auth_user_request->setDenyMessage("Request denied because you provided an empty password. Users MUST have a password.");
        }
    }

    xfree(cleartext);

    if (!local_basic->valid()) {
        lb->auth_type = AUTH_BROKEN;
        auth_user_request->user(lb);
        return auth_user_request;
    }

    /* now lookup and see if we have a matching auth_user structure in memory. */
    AuthUser::Pointer auth_user;

    if ((auth_user = authBasicAuthUserFindUsername(lb->username())) == NULL) {
        /* the user doesn't exist in the username cache yet */
        /* save the credentials */
        debugs(29, 9, HERE << "Creating new user '" << lb->username() << "'");
        /* set the auth_user type */
        lb->auth_type = AUTH_BASIC;
        /* current time for timeouts */
        lb->expiretime = current_time.tv_sec;

        /* this basic_user struct is the 'lucky one' to get added to the username cache */
        /* the requests after this link to the basic_user */
        /* store user in hash */
        lb->addToNameCache();

        auth_user = lb;
        assert(auth_user != NULL);
    } else {
        /* replace the current cached password with the new one */
        BasicUser *basic_auth = dynamic_cast<BasicUser *>(auth_user.getRaw());
        assert(basic_auth);
        basic_auth->updateCached(local_basic);
        auth_user = basic_auth;
    }

    /* link the request to the in-cache user */
    auth_user_request->user(auth_user);
    return auth_user_request;
}

/** Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
AuthBasicConfig::init(AuthConfig * schemeCfg)
{
    if (authenticateProgram) {
        authbasic_initialised = 1;

        if (basicauthenticators == NULL)
            basicauthenticators = new helper("basicauthenticator");

        basicauthenticators->cmdline = authenticateProgram;

        basicauthenticators->childs = authenticateChildren;

        basicauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(basicauthenticators);

        CBDATA_INIT_TYPE(authenticateStateData);
    }
}

void
AuthBasicConfig::registerWithCacheManager(void)
{
    Mgr::RegisterAction("basicauthenticator",
                        "Basic User Authenticator Stats",
                        authenticateBasicStats, 0, 1);
}

void
BasicUser::queueRequest(AuthUserRequest::Pointer auth_user_request, RH * handler, void *data)
{
    BasicAuthQueueNode *node;
    node = static_cast<BasicAuthQueueNode *>(xcalloc(1, sizeof(BasicAuthQueueNode)));
    assert(node);
    /* save the details */
    node->next = auth_queue;
    auth_queue = node;
    node->auth_user_request = auth_user_request;
    node->handler = handler;
    node->data = cbdataReference(data);
}

void
BasicUser::submitRequest(AuthUserRequest::Pointer auth_user_request, RH * handler, void *data)
{
    /* mark the user as having verification in progress */
    credentials(Pending);
    authenticateStateData *r = NULL;
    char buf[8192];
    char user[1024], pass[1024];
    r = cbdataAlloc(authenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = auth_user_request;
    if (static_cast<AuthBasicConfig*>(config)->utf8) {
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
