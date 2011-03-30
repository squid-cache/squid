/*
 * $Id$
 *
 * DEBUG: section 29    Authenticator
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
#include "rfc2617.h"
#include "auth/digest/auth_digest.h"
#include "auth/digest/Scheme.h"
#include "auth/digest/UserRequest.h"
#include "auth/Gadgets.h"
#include "base64.h"
#include "event.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "wordlist.h"
#include "SquidTime.h"

/* Digest Scheme */

static AUTHSSTATS authenticateDigestStats;

helper *digestauthenticators = NULL;

static hash_table *digest_nonce_cache;

static int authdigest_initialised = 0;
static MemAllocator *digest_nonce_pool = NULL;

// CBDATA_TYPE(DigestAuthenticateStateData);

enum http_digest_attr_type {
    DIGEST_USERNAME,
    DIGEST_REALM,
    DIGEST_QOP,
    DIGEST_ALGORITHM,
    DIGEST_URI,
    DIGEST_NONCE,
    DIGEST_NC,
    DIGEST_CNONCE,
    DIGEST_RESPONSE,
    DIGEST_ENUM_END
};

static const HttpHeaderFieldAttrs DigestAttrs[DIGEST_ENUM_END] = {
    {"username",  (http_hdr_type)DIGEST_USERNAME},
    {"realm", (http_hdr_type)DIGEST_REALM},
    {"qop", (http_hdr_type)DIGEST_QOP},
    {"algorithm", (http_hdr_type)DIGEST_ALGORITHM},
    {"uri", (http_hdr_type)DIGEST_URI},
    {"nonce", (http_hdr_type)DIGEST_NONCE},
    {"nc", (http_hdr_type)DIGEST_NC},
    {"cnonce", (http_hdr_type)DIGEST_CNONCE},
    {"response", (http_hdr_type)DIGEST_RESPONSE},
};

static HttpHeaderFieldInfo *DigestFieldsInfo = NULL;

/*
 *
 * Nonce Functions
 *
 */

static void authenticateDigestNonceCacheCleanup(void *data);
static digest_nonce_h *authenticateDigestNonceFindNonce(const char *nonceb64);
static digest_nonce_h *authenticateDigestNonceNew(void);
static void authenticateDigestNonceDelete(digest_nonce_h * nonce);
static void authenticateDigestNonceSetup(void);
static void authenticateDigestNonceShutdown(void);
static void authenticateDigestNonceReconfigure(void);
static int authDigestNonceIsStale(digest_nonce_h * nonce);
static void authDigestNonceEncode(digest_nonce_h * nonce);
static void authDigestNonceLink(digest_nonce_h * nonce);
#if NOT_USED
static int authDigestNonceLinks(digest_nonce_h * nonce);
#endif
static void authDigestNonceUserUnlink(digest_nonce_h * nonce);
static void authDigestNoncePurge(digest_nonce_h * nonce);

static void
authDigestNonceEncode(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (nonce->key)
        xfree(nonce->key);

    nonce->key = xstrdup(base64_encode_bin((char *) &(nonce->noncedata), sizeof(digest_nonce_data)));
}

static digest_nonce_h *
authenticateDigestNonceNew(void)
{
    digest_nonce_h *newnonce = static_cast < digest_nonce_h * >(digest_nonce_pool->alloc());
    digest_nonce_h *temp;

    /* NONCE CREATION - NOTES AND REASONING. RBC 20010108
     * === EXCERPT FROM RFC 2617 ===
     * The contents of the nonce are implementation dependent. The quality
     * of the implementation depends on a good choice. A nonce might, for
     * example, be constructed as the base 64 encoding of
     *
     * time-stamp H(time-stamp ":" ETag ":" private-key)
     *
     * where time-stamp is a server-generated time or other non-repeating
     * value, ETag is the value of the HTTP ETag header associated with
     * the requested entity, and private-key is data known only to the
     * server.  With a nonce of this form a server would recalculate the
     * hash portion after receiving the client authentication header and
     * reject the request if it did not match the nonce from that header
     * or if the time-stamp value is not recent enough. In this way the
     * server can limit the time of the nonce's validity. The inclusion of
     * the ETag prevents a replay request for an updated version of the
     * resource.  (Note: including the IP address of the client in the
     * nonce would appear to offer the server the ability to limit the
     * reuse of the nonce to the same client that originally got it.
     * However, that would break proxy farms, where requests from a single
     * user often go through different proxies in the farm. Also, IP
     * address spoofing is not that hard.)
     * ====
     *
     * Now for my reasoning:
     * We will not accept a unrecognised nonce->we have all recognisable
     * nonces stored. If we send out unique base64 encodings we guarantee
     * that a given nonce applies to only one user (barring attacks or
     * really bad timing with expiry and creation).  Using a random
     * component in the nonce allows us to loop to find a unique nonce.
     * We use H(nonce_data) so the nonce is meaningless to the reciever.
     * So our nonce looks like base64(H(timestamp,pointertohash,randomdata))
     * And even if our randomness is not very random (probably due to
     * bad coding on my part) we don't really care - the timestamp and
     * memory pointer also guarantee local uniqueness in the input to the hash
     * function.
     */

    /* create a new nonce */
    newnonce->nc = 0;
    newnonce->flags.valid = 1;
    newnonce->noncedata.self = newnonce;
    newnonce->noncedata.creationtime = current_time.tv_sec;
    newnonce->noncedata.randomdata = squid_random();

    authDigestNonceEncode(newnonce);
    /*
     * loop until we get a unique nonce. The nonce creation must
     * have a random factor
     */

    while ((temp = authenticateDigestNonceFindNonce((char const *) (newnonce->key)))) {
        /* create a new nonce */
        newnonce->noncedata.randomdata = squid_random();
        authDigestNonceEncode(newnonce);
    }

    hash_join(digest_nonce_cache, newnonce);
    /* the cache's link */
    authDigestNonceLink(newnonce);
    newnonce->flags.incache = 1;
    debugs(29, 5, "authenticateDigestNonceNew: created nonce " << newnonce << " at " << newnonce->noncedata.creationtime);
    return newnonce;
}

static void
authenticateDigestNonceDelete(digest_nonce_h * nonce)
{
    if (nonce) {
        assert(nonce->references == 0);
#if UNREACHABLECODE

        if (nonce->flags.incache)
            hash_remove_link(digest_nonce_cache, nonce);

#endif

        assert(nonce->flags.incache == 0);

        safe_free(nonce->key);

        digest_nonce_pool->freeOne(nonce);
    }
}

static void
authenticateDigestNonceSetup(void)
{
    if (!digest_nonce_pool)
        digest_nonce_pool = memPoolCreate("Digest Scheme nonce's", sizeof(digest_nonce_h));

    if (!digest_nonce_cache) {
        digest_nonce_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
        assert(digest_nonce_cache);
        eventAdd("Digest none cache maintenance", authenticateDigestNonceCacheCleanup, NULL, static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->nonceGCInterval, 1);
    }
}

static void
authenticateDigestNonceShutdown(void)
{
    /*
     * We empty the cache of any nonces left in there.
     */
    digest_nonce_h *nonce;

    if (digest_nonce_cache) {
        debugs(29, 2, "authenticateDigestNonceShutdown: Shutting down nonce cache ");
        hash_first(digest_nonce_cache);

        while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
            assert(nonce->flags.incache);
            authDigestNoncePurge(nonce);
        }
    }

#if DEBUGSHUTDOWN
    if (digest_nonce_pool) {
        delete digest_nonce_pool;
        digest_nonce_pool = NULL;
    }

#endif
    debugs(29, 2, "authenticateDigestNonceShutdown: Nonce cache shutdown");
}

static void
authenticateDigestNonceReconfigure(void)
{}

static void
authenticateDigestNonceCacheCleanup(void *data)
{
    /*
     * We walk the hash by nonceb64 as that is the unique key we
     * use.  For big hash tables we could consider stepping through
     * the cache, 100/200 entries at a time. Lets see how it flies
     * first.
     */
    digest_nonce_h *nonce;
    debugs(29, 3, "authenticateDigestNonceCacheCleanup: Cleaning the nonce cache now");
    debugs(29, 3, "authenticateDigestNonceCacheCleanup: Current time: " << current_time.tv_sec);
    hash_first(digest_nonce_cache);

    while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
        debugs(29, 3, "authenticateDigestNonceCacheCleanup: nonce entry  : " << nonce << " '" << (char *) nonce->key << "'");
        debugs(29, 4, "authenticateDigestNonceCacheCleanup: Creation time: " << nonce->noncedata.creationtime);

        if (authDigestNonceIsStale(nonce)) {
            debugs(29, 4, "authenticateDigestNonceCacheCleanup: Removing nonce " << (char *) nonce->key << " from cache due to timeout.");
            assert(nonce->flags.incache);
            /* invalidate nonce so future requests fail */
            nonce->flags.valid = 0;
            /* if it is tied to a auth_user, remove the tie */
            authDigestNonceUserUnlink(nonce);
            authDigestNoncePurge(nonce);
        }
    }

    debugs(29, 3, "authenticateDigestNonceCacheCleanup: Finished cleaning the nonce cache.");

    if (static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->active())
        eventAdd("Digest none cache maintenance", authenticateDigestNonceCacheCleanup, NULL, static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->nonceGCInterval, 1);
}

static void
authDigestNonceLink(digest_nonce_h * nonce)
{
    assert(nonce != NULL);
    nonce->references++;
    debugs(29, 9, "authDigestNonceLink: nonce '" << nonce << "' now at '" << nonce->references << "'.");
}

#if NOT_USED
static int
authDigestNonceLinks(digest_nonce_h * nonce)
{
    if (!nonce)
        return -1;

    return nonce->references;
}

#endif

void
authDigestNonceUnlink(digest_nonce_h * nonce)
{
    assert(nonce != NULL);

    if (nonce->references > 0) {
        nonce->references--;
    } else {
        debugs(29, 1, "authDigestNonceUnlink; Attempt to lower nonce " << nonce << " refcount below 0!");
    }

    debugs(29, 9, "authDigestNonceUnlink: nonce '" << nonce << "' now at '" << nonce->references << "'.");

    if (nonce->references == 0)
        authenticateDigestNonceDelete(nonce);
}

const char *
authenticateDigestNonceNonceb64(const digest_nonce_h * nonce)
{
    if (!nonce)
        return NULL;

    return (char const *) nonce->key;
}

static digest_nonce_h *
authenticateDigestNonceFindNonce(const char *nonceb64)
{
    digest_nonce_h *nonce = NULL;

    if (nonceb64 == NULL)
        return NULL;

    debugs(29, 9, "authDigestNonceFindNonce:looking for nonceb64 '" << nonceb64 << "' in the nonce cache.");

    nonce = static_cast < digest_nonce_h * >(hash_lookup(digest_nonce_cache, nonceb64));

    if ((nonce == NULL) || (strcmp(authenticateDigestNonceNonceb64(nonce), nonceb64)))
        return NULL;

    debugs(29, 9, "authDigestNonceFindNonce: Found nonce '" << nonce << "'");

    return nonce;
}

int
authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9])
{
    unsigned long intnc;
    /* do we have a nonce ? */

    if (!nonce)
        return 0;

    intnc = strtol(nc, NULL, 16);

    /* has it already been invalidated ? */
    if (!nonce->flags.valid) {
        debugs(29, 4, "authDigestNonceIsValid: Nonce already invalidated");
        return 0;
    }

    /* is the nonce-count ok ? */
    if (!static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->CheckNonceCount) {
        nonce->nc++;
        return -1;              /* forced OK by configuration */
    }

    if ((static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->NonceStrictness && intnc != nonce->nc + 1) ||
            intnc < nonce->nc + 1) {
        debugs(29, 4, "authDigestNonceIsValid: Nonce count doesn't match");
        nonce->flags.valid = 0;
        return 0;
    }

    /* seems ok */
    /* increment the nonce count - we've already checked that intnc is a
     *  valid representation for us, so we don't need the test here.
     */
    nonce->nc = intnc;

    return -1;
}

static int
authDigestNonceIsStale(digest_nonce_h * nonce)
{
    /* do we have a nonce ? */

    if (!nonce)
        return -1;

    /* has it's max duration expired? */
    if (nonce->noncedata.creationtime + static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->noncemaxduration < current_time.tv_sec) {
        debugs(29, 4, "authDigestNonceIsStale: Nonce is too old. " <<
               nonce->noncedata.creationtime << " " <<
               static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->noncemaxduration << " " <<
               current_time.tv_sec);

        nonce->flags.valid = 0;
        return -1;
    }

    if (nonce->nc > 99999998) {
        debugs(29, 4, "authDigestNonceIsStale: Nonce count overflow");
        nonce->flags.valid = 0;
        return -1;
    }

    if (nonce->nc > static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->noncemaxuses) {
        debugs(29, 4, "authDigestNoncelastRequest: Nonce count over user limit");
        nonce->flags.valid = 0;
        return -1;
    }

    /* seems ok */
    return 0;
}

/**
 * \retval  0    the digest is not stale yet
 * \retval -1    the digest will be stale on the next request
 */
int
authDigestNonceLastRequest(digest_nonce_h * nonce)
{
    if (!nonce)
        return -1;

    if (nonce->nc == 99999997) {
        debugs(29, 4, "authDigestNoncelastRequest: Nonce count about to overflow");
        return -1;
    }

    if (nonce->nc >= static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->noncemaxuses - 1) {
        debugs(29, 4, "authDigestNoncelastRequest: Nonce count about to hit user limit");
        return -1;
    }

    /* and other tests are possible. */
    return 0;
}

static void
authDigestNoncePurge(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (!nonce->flags.incache)
        return;

    hash_remove_link(digest_nonce_cache, nonce);

    nonce->flags.incache = 0;

    /* the cache's link */
    authDigestNonceUnlink(nonce);
}

/* USER related functions */
static AuthUser::Pointer
authDigestUserFindUsername(const char *username)
{
    AuthUserHashPointer *usernamehash;
    debugs(29, 9, HERE << "Looking for user '" << username << "'");

    if (username && (usernamehash = static_cast < auth_user_hash_pointer * >(hash_lookup(proxy_auth_username_cache, username)))) {
        while ((usernamehash->user()->auth_type != Auth::AUTH_DIGEST) && (usernamehash->next))
            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);

        if (usernamehash->user()->auth_type == Auth::AUTH_DIGEST) {
            return usernamehash->user();
        }
    }

    return NULL;
}

void
AuthDigestConfig::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (digestauthenticators) {
        helperShutdown(digestauthenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

/** delete the digest request structure. Does NOT delete related structures */
void
digestScheme::done()
{
    /** \todo this should be a Config call. */

    if (digestauthenticators)
        helperShutdown(digestauthenticators);

    if (DigestFieldsInfo) {
        httpHeaderDestroyFieldsInfo(DigestFieldsInfo, DIGEST_ENUM_END);
        DigestFieldsInfo = NULL;
    }

    authdigest_initialised = 0;

    if (!shutting_down) {
        authenticateDigestNonceReconfigure();
        return;
    }

    delete digestauthenticators;
    digestauthenticators = NULL;

    PurgeCredentialsCache();
    authenticateDigestNonceShutdown();
    debugs(29, 2, "authenticateDigestDone: Digest authentication shut down.");

    /* clear the global handle to this scheme. */
    _instance = NULL;
}

void
AuthDigestConfig::dump(StoreEntry * entry, const char *name, AuthConfig * scheme)
{
    wordlist *list = authenticateProgram;
    debugs(29, 9, "authDigestCfgDump: Dumping configuration");
    storeAppendPrintf(entry, "%s %s", name, "digest");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n%s %s realm %s\n%s %s children %d startup=%d idle=%d concurrency=%d\n%s %s nonce_max_count %d\n%s %s nonce_max_duration %d seconds\n%s %s nonce_garbage_interval %d seconds\n",
                      name, "digest", digestAuthRealm,
                      name, "digest", authenticateChildren.n_max, authenticateChildren.n_startup, authenticateChildren.n_idle, authenticateChildren.concurrency,
                      name, "digest", noncemaxuses,
                      name, "digest", (int) noncemaxduration,
                      name, "digest", (int) nonceGCInterval);
}

bool
AuthDigestConfig::active() const
{
    return authdigest_initialised == 1;
}

bool
AuthDigestConfig::configured() const
{
    if ((authenticateProgram != NULL) &&
            (authenticateChildren.n_max != 0) &&
            (digestAuthRealm != NULL) && (noncemaxduration > -1))
        return true;

    return false;
}

/* add the [www-|Proxy-]authenticate header on a 407 or 401 reply */
void
AuthDigestConfig::fixHeader(AuthUserRequest::Pointer auth_user_request, HttpReply *rep, http_hdr_type hdrType, HttpRequest * request)
{
    if (!authenticateProgram)
        return;

    int stale = 0;

    if (auth_user_request != NULL) {
        AuthDigestUserRequest *digest_request;
        digest_request = dynamic_cast<AuthDigestUserRequest*>(auth_user_request.getRaw());
        assert (digest_request != NULL);

        stale = !digest_request->flags.invalid_password;
    }

    /* on a 407 or 401 we always use a new nonce */
    digest_nonce_h *nonce = authenticateDigestNonceNew();

    debugs(29, 9, "authenticateFixHeader: Sending type:" << hdrType <<
           " header: 'Digest realm=\"" << digestAuthRealm << "\", nonce=\"" <<
           authenticateDigestNonceNonceb64(nonce) << "\", qop=\"" << QOP_AUTH <<
           "\", stale=" << (stale ? "true" : "false"));

    /* in the future, for WWW auth we may want to support the domain entry */
    httpHeaderPutStrf(&rep->header, hdrType, "Digest realm=\"%s\", nonce=\"%s\", qop=\"%s\", stale=%s", digestAuthRealm, authenticateDigestNonceNonceb64(nonce), QOP_AUTH, stale ? "true" : "false");
}

DigestUser::~DigestUser()
{
    dlink_node *link, *tmplink;
    link = nonces.head;

    while (link) {
        tmplink = link;
        link = link->next;
        dlinkDelete(tmplink, &nonces);
        authDigestNoncePurge(static_cast < digest_nonce_h * >(tmplink->data));
        authDigestNonceUnlink(static_cast < digest_nonce_h * >(tmplink->data));
        dlinkNodeDelete(tmplink);
    }
}

int32_t
DigestUser::ttl() const
{
    int32_t global_ttl = static_cast<int32_t>(expiretime - squid_curtime + Config.authenticateTTL);

    /* find the longest lasting nonce. */
    int32_t latest_nonce = -1;
    dlink_node *link = nonces.head;
    while (link) {
        digest_nonce_h *nonce = static_cast<digest_nonce_h *>(link->data);
        if (nonce->flags.valid && nonce->noncedata.creationtime > latest_nonce)
            latest_nonce = nonce->noncedata.creationtime;

        link = link->next;
    }
    if (latest_nonce == -1)
        return min(-1, global_ttl);

    int32_t nonce_ttl = latest_nonce - current_time.tv_sec + static_cast<AuthDigestConfig*>(AuthConfig::Find("digest"))->noncemaxduration;

    return min(nonce_ttl, global_ttl);
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
AuthDigestConfig::init(AuthConfig * scheme)
{
    if (authenticateProgram) {
        DigestFieldsInfo = httpHeaderBuildFieldsInfo(DigestAttrs, DIGEST_ENUM_END);
        authenticateDigestNonceSetup();
        authdigest_initialised = 1;

        if (digestauthenticators == NULL)
            digestauthenticators = new helper("digestauthenticator");

        digestauthenticators->cmdline = authenticateProgram;

        digestauthenticators->childs = authenticateChildren;

        digestauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(digestauthenticators);

        CBDATA_INIT_TYPE(authenticateStateData);
    }
}

void
AuthDigestConfig::registerWithCacheManager(void)
{
    Mgr::RegisterAction("digestauthenticator",
                        "Digest User Authenticator Stats",
                        authenticateDigestStats, 0, 1);
}

/* free any allocated configuration details */
void
AuthDigestConfig::done()
{
    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);

    safe_free(digestAuthRealm);
}

AuthDigestConfig::AuthDigestConfig()
{
    /* TODO: move into initialisation list */
    /* 5 minutes */
    nonceGCInterval = 5 * 60;
    /* 30 minutes */
    noncemaxduration = 30 * 60;
    /* 50 requests */
    noncemaxuses = 50;
    /* Not strict nonce count behaviour */
    NonceStrictness = 0;
    /* Verify nonce count */
    CheckNonceCount = 1;
}

void
AuthDigestConfig::parse(AuthConfig * scheme, int n_configured, char *param_str)
{
    if (strcasecmp(param_str, "program") == 0) {
        if (authenticateProgram)
            wordlistDestroy(&authenticateProgram);

        parse_wordlist(&authenticateProgram);

        requirePathnameExists("auth_param digest program", authenticateProgram->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        authenticateChildren.parseConfig();
    } else if (strcasecmp(param_str, "realm") == 0) {
        parse_eol(&digestAuthRealm);
    } else if (strcasecmp(param_str, "nonce_garbage_interval") == 0) {
        parse_time_t(&nonceGCInterval);
    } else if (strcasecmp(param_str, "nonce_max_duration") == 0) {
        parse_time_t(&noncemaxduration);
    } else if (strcasecmp(param_str, "nonce_max_count") == 0) {
        parse_int((int *) &noncemaxuses);
    } else if (strcasecmp(param_str, "nonce_strictness") == 0) {
        parse_onoff(&NonceStrictness);
    } else if (strcasecmp(param_str, "check_nonce_count") == 0) {
        parse_onoff(&CheckNonceCount);
    } else if (strcasecmp(param_str, "post_workaround") == 0) {
        parse_onoff(&PostWorkaround);
    } else if (strcasecmp(param_str, "utf8") == 0) {
        parse_onoff(&utf8);
    } else {
        debugs(29, 0, "unrecognised digest auth scheme parameter '" << param_str << "'");
    }
}

const char *
AuthDigestConfig::type() const
{
    return digestScheme::GetInstance()->type();
}


static void
authenticateDigestStats(StoreEntry * sentry)
{
    helperStats(sentry, digestauthenticators, "Digest Authenticator Statistics");
}

/* NonceUserUnlink: remove the reference to auth_user and unlink the node from the list */

static void
authDigestNonceUserUnlink(digest_nonce_h * nonce)
{
    DigestUser *digest_user;
    dlink_node *link, *tmplink;

    if (!nonce)
        return;

    if (!nonce->user)
        return;

    digest_user = nonce->user;

    /* unlink from the user list. Yes we're crossing structures but this is the only
     * time this code is needed
     */
    link = digest_user->nonces.head;

    while (link) {
        tmplink = link;
        link = link->next;

        if (tmplink->data == nonce) {
            dlinkDelete(tmplink, &digest_user->nonces);
            authDigestNonceUnlink(static_cast < digest_nonce_h * >(tmplink->data));
            dlinkNodeDelete(tmplink);
            link = NULL;
        }
    }

    /* this reference to user was not locked because freeeing the user frees
     * the nonce too.
     */
    nonce->user = NULL;
}

/* authDigestUserLinkNonce: add a nonce to a given user's struct */

static void
authDigestUserLinkNonce(DigestUser * user, digest_nonce_h * nonce)
{
    dlink_node *node;
    DigestUser *digest_user;

    if (!user || !nonce)
        return;

    digest_user = user;

    node = digest_user->nonces.head;

    while (node && (node->data != nonce))
        node = node->next;

    if (node)
        return;

    node = dlinkNodeNew();

    dlinkAddTail(nonce, node, &digest_user->nonces);

    authDigestNonceLink(nonce);

    /* ping this nonce to this auth user */
    assert((nonce->user == NULL) || (nonce->user == user));

    /* we don't lock this reference because removing the user removes the
     * hash too. Of course if that changes we're stuffed so read the code huh?
     */
    nonce->user = user;
}

/* setup the necessary info to log the username */
static AuthUserRequest::Pointer
authDigestLogUsername(char *username, AuthUserRequest::Pointer auth_user_request)
{
    assert(auth_user_request != NULL);

    /* log the username */
    debugs(29, 9, "authDigestLogUsername: Creating new user for logging '" << username << "'");
    AuthUser::Pointer digest_user = new DigestUser(static_cast<AuthDigestConfig*>(AuthConfig::Find("digest")));
    /* save the credentials */
    digest_user->username(username);
    /* set the auth_user type */
    digest_user->auth_type = Auth::AUTH_BROKEN;
    /* link the request to the user */
    auth_user_request->user(digest_user);
    return auth_user_request;
}

/*
 * Decode a Digest [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
AuthUserRequest::Pointer
AuthDigestConfig::decode(char const *proxy_auth)
{
    const char *item;
    const char *p;
    const char *pos = NULL;
    char *username = NULL;
    digest_nonce_h *nonce;
    int ilen;

    debugs(29, 9, "authenticateDigestDecodeAuth: beginning");

    AuthDigestUserRequest *digest_request = new AuthDigestUserRequest();

    /* trim DIGEST from string */

    while (xisgraph(*proxy_auth))
        proxy_auth++;

    /* Trim leading whitespace before decoding */
    while (xisspace(*proxy_auth))
        proxy_auth++;

    String temp(proxy_auth);

    while (strListGetItem(&temp, ',', &item, &ilen, &pos)) {
        /* isolate directive name & value */
        size_t nlen;
        size_t vlen;
        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen)) {
            nlen = p++ - item;
            vlen = ilen - (p - item);
        } else {
            nlen = ilen;
            vlen = 0;
        }

        /* parse value. auth-param     = token "=" ( token | quoted-string ) */
        String value;
        if (vlen > 0) {
            if (*p == '"') {
                if (!httpHeaderParseQuotedString(p, vlen, &value)) {
                    debugs(29, 9, "authDigestDecodeAuth: Failed to parse attribute '" << item << "' in '" << temp << "'");
                    continue;
                }
            } else {
                value.limitInit(p, vlen);
            }
        } else {
            debugs(29, 9, "authDigestDecodeAuth: Failed to parse attribute '" << item << "' in '" << temp << "'");
            continue;
        }

        /* find type */
        http_digest_attr_type type = (http_digest_attr_type)httpHeaderIdByName(item, nlen, DigestFieldsInfo, DIGEST_ENUM_END);

        switch (type) {
        case DIGEST_USERNAME:
            safe_free(username);
            username = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found Username '" << username << "'");
            break;

        case DIGEST_REALM:
            safe_free(digest_request->realm);
            digest_request->realm = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found realm '" << digest_request->realm << "'");
            break;

        case DIGEST_QOP:
            safe_free(digest_request->qop);
            digest_request->qop = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found qop '" << digest_request->qop << "'");
            break;

        case DIGEST_ALGORITHM:
            safe_free(digest_request->algorithm);
            digest_request->algorithm = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found algorithm '" << digest_request->algorithm << "'");
            break;

        case DIGEST_URI:
            safe_free(digest_request->uri);
            digest_request->uri = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found uri '" << digest_request->uri << "'");
            break;

        case DIGEST_NONCE:
            safe_free(digest_request->nonceb64);
            digest_request->nonceb64 = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found nonce '" << digest_request->nonceb64 << "'");
            break;

        case DIGEST_NC:
            if (value.size() != 8) {
                debugs(29, 9, "authDigestDecodeAuth: Invalid nc '" << value << "' in '" << temp << "'");
            }
            xstrncpy(digest_request->nc, value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found noncecount '" << digest_request->nc << "'");
            break;

        case DIGEST_CNONCE:
            safe_free(digest_request->cnonce);
            digest_request->cnonce = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found cnonce '" << digest_request->cnonce << "'");
            break;

        case DIGEST_RESPONSE:
            safe_free(digest_request->response);
            digest_request->response = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "authDigestDecodeAuth: Found response '" << digest_request->response << "'");
            break;

        default:
            debugs(29, 3, "authDigestDecodeAuth: Unknown attribute '" << item << "' in '" << temp << "'");
            break;
        }
    }

    temp.clean();


    /* now we validate the data given to us */

    /*
     * TODO: on invalid parameters we should return 400, not 407.
     * Find some clean way of doing this. perhaps return a valid
     * struct, and set the direction to clientwards combined with
     * a change to the clientwards handling code (ie let the
     * clientwards call set the error type (but limited to known
     * correct values - 400/401/407
     */

    /* 2069 requirements */

    /* do we have a username ? */
    if (!username || username[0] == '\0') {
        debugs(29, 2, "authenticateDigestDecode: Empty or not present username");
        return authDigestLogUsername(username, digest_request);
    }

    /* Sanity check of the username.
     * " can not be allowed in usernames until * the digest helper protocol
     * have been redone
     */
    if (strchr(username, '"')) {
        debugs(29, 2, "authenticateDigestDecode: Unacceptable username '" << username << "'");
        return authDigestLogUsername(username, digest_request);
    }

    /* do we have a realm ? */
    if (!digest_request->realm || digest_request->realm[0] == '\0') {
        debugs(29, 2, "authenticateDigestDecode: Empty or not present realm");
        return authDigestLogUsername(username, digest_request);
    }

    /* and a nonce? */
    if (!digest_request->nonceb64 || digest_request->nonceb64[0] == '\0') {
        debugs(29, 2, "authenticateDigestDecode: Empty or not present nonce");
        return authDigestLogUsername(username, digest_request);
    }

    /* we can't check the URI just yet. We'll check it in the
     * authenticate phase, but needs to be given */
    if (!digest_request->uri || digest_request->uri[0] == '\0') {
        debugs(29, 2, "authenticateDigestDecode: Missing URI field");
        return authDigestLogUsername(username, digest_request);
    }

    /* is the response the correct length? */
    if (!digest_request->response || strlen(digest_request->response) != 32) {
        debugs(29, 2, "authenticateDigestDecode: Response length invalid");
        return authDigestLogUsername(username, digest_request);
    }

    /* check the algorithm is present and supported */
    if (!digest_request->algorithm)
        digest_request->algorithm = xstrndup("MD5", 4);
    else if (strcmp(digest_request->algorithm, "MD5")
             && strcmp(digest_request->algorithm, "MD5-sess")) {
        debugs(29, 2, "authenticateDigestDecode: invalid algorithm specified!");
        return authDigestLogUsername(username, digest_request);
    }

    /* 2617 requirements, indicated by qop */
    if (digest_request->qop) {

        /* check the qop is what we expected. */
        if (strcmp(digest_request->qop, QOP_AUTH) != 0) {
            /* we received a qop option we didn't send */
            debugs(29, 2, "authenticateDigestDecode: Invalid qop option received");
            return authDigestLogUsername(username, digest_request);
        }

        /* check cnonce */
        if (!digest_request->cnonce || digest_request->cnonce[0] == '\0') {
            debugs(29, 2, "authenticateDigestDecode: Missing cnonce field");
            return authDigestLogUsername(username, digest_request);
        }

        /* check nc */
        if (strlen(digest_request->nc) != 8 || strspn(digest_request->nc, "0123456789abcdefABCDEF") != 8) {
            debugs(29, 2, "authenticateDigestDecode: invalid nonce count");
            return authDigestLogUsername(username, digest_request);
        }
    } else {
        /* cnonce and nc both require qop */
        if (digest_request->cnonce || digest_request->nc) {
            debugs(29, 2, "authenticateDigestDecode: missing qop!");
            return authDigestLogUsername(username, digest_request);
        }
    }

    /** below nonce state dependent **/

    /* now the nonce */
    nonce = authenticateDigestNonceFindNonce(digest_request->nonceb64);
    if (!nonce) {
        /* we couldn't find a matching nonce! */
        debugs(29, 2, "authenticateDigestDecode: Unexpected or invalid nonce received");
        if (digest_request->user() != NULL)
            digest_request->user()->credentials(AuthUser::Failed);
        return authDigestLogUsername(username, digest_request);
    }

    digest_request->nonce = nonce;
    authDigestNonceLink(nonce);

    /* check that we're not being hacked / the username hasn't changed */
    if (nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "authenticateDigestDecode: Username for the nonce does not equal the username for the request");
        return authDigestLogUsername(username, digest_request);
    }

    /* the method we'll check at the authenticate step as well */


    /* we don't send or parse opaques. Ok so we're flexable ... */

    /* find the user */
    DigestUser *digest_user;

    AuthUser::Pointer auth_user;

    if ((auth_user = authDigestUserFindUsername(username)) == NULL) {
        /* the user doesn't exist in the username cache yet */
        debugs(29, 9, "authDigestDecodeAuth: Creating new digest user '" << username << "'");
        digest_user = new DigestUser(this);
        /* auth_user is a parent */
        auth_user = digest_user;
        /* save the username */
        digest_user->username(username);
        /* set the user type */
        digest_user->auth_type = Auth::AUTH_DIGEST;
        /* this auth_user struct is the one to get added to the
         * username cache */
        /* store user in hash's */
        digest_user->addToNameCache();

        /*
         * Add the digest to the user so we can tell if a hacking
         * or spoofing attack is taking place. We do this by assuming
         * the user agent won't change user name without warning.
         */
        authDigestUserLinkNonce(digest_user, nonce);
    } else {
        debugs(29, 9, "authDigestDecodeAuth: Found user '" << username << "' in the user cache as '" << auth_user << "'");
        digest_user = static_cast<DigestUser *>(auth_user.getRaw());
        xfree(username);
    }

    /*link the request and the user */
    assert(digest_request != NULL);

    digest_request->user(digest_user);
    debugs(29, 9, "username = '" << digest_user->username() << "'\nrealm = '" <<
           digest_request->realm << "'\nqop = '" << digest_request->qop <<
           "'\nalgorithm = '" << digest_request->algorithm << "'\nuri = '" <<
           digest_request->uri << "'\nnonce = '" << digest_request->nonceb64 <<
           "'\nnc = '" << digest_request->nc << "'\ncnonce = '" <<
           digest_request->cnonce << "'\nresponse = '" <<
           digest_request->response << "'\ndigestnonce = '" << nonce << "'");

    return digest_request;
}

DigestUser::DigestUser(AuthConfig *aConfig) : AuthUser(aConfig), HA1created (0)
{}
