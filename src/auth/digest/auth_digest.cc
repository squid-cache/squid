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
#include "auth_digest.h"
#include "auth/Gadgets.h"
#include "event.h"
#include "CacheManager.h"
#include "Store.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "wordlist.h"
#include "SquidTime.h"
/* TODO don't include this */
#include "digestScheme.h"

/* Digest Scheme */

static HLPCB authenticateDigestHandleReply;
static AUTHSSTATS authenticateDigestStats;

static helper *digestauthenticators = NULL;

static hash_table *digest_nonce_cache;

static AuthDigestConfig digestConfig;

static int authdigest_initialised = 0;
static MemAllocator *digest_nonce_pool = NULL;

CBDATA_TYPE(DigestAuthenticateStateData);

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
static const char *authenticateDigestNonceNonceb64(digest_nonce_h * nonce);
static int authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9]);
static int authDigestNonceIsStale(digest_nonce_h * nonce);
static void authDigestNonceEncode(digest_nonce_h * nonce);
static int authDigestNonceLastRequest(digest_nonce_h * nonce);
static void authDigestNonceLink(digest_nonce_h * nonce);
static void authDigestNonceUnlink(digest_nonce_h * nonce);
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

        digest_nonce_pool->free(nonce);
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
        eventAdd("Digest none cache maintenance", authenticateDigestNonceCacheCleanup, NULL, digestConfig.nonceGCInterval, 1);
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

    if (digestConfig.active())
        eventAdd("Digest none cache maintenance", authenticateDigestNonceCacheCleanup, NULL, digestConfig.nonceGCInterval, 1);
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

static void
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

static const char *
authenticateDigestNonceNonceb64(digest_nonce_h * nonce)
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

static int
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
    if (!digestConfig.CheckNonceCount) {
        nonce->nc++;
        return -1;              /* forced OK by configuration */
    }

    if ((digestConfig.NonceStrictness && intnc != nonce->nc + 1) ||
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
    if (nonce->noncedata.creationtime + digestConfig.noncemaxduration < current_time.tv_sec) {
        debugs(29, 4, "authDigestNonceIsStale: Nonce is too old. " <<
               nonce->noncedata.creationtime << " " <<
               digestConfig.noncemaxduration << " " <<
               current_time.tv_sec);

        nonce->flags.valid = 0;
        return -1;
    }

    if (nonce->nc > 99999998) {
        debugs(29, 4, "authDigestNonceIsStale: Nonce count overflow");
        nonce->flags.valid = 0;
        return -1;
    }

    if (nonce->nc > digestConfig.noncemaxuses) {
        debugs(29, 4, "authDigestNoncelastRequest: Nonce count over user limit");
        nonce->flags.valid = 0;
        return -1;
    }

    /* seems ok */
    return 0;
}

/* return -1 if the digest will be stale on the next request */
static int
authDigestNonceLastRequest(digest_nonce_h * nonce)
{
    if (!nonce)
        return -1;

    if (nonce->nc == 99999997) {
        debugs(29, 4, "authDigestNoncelastRequest: Nonce count about to overflow");
        return -1;
    }

    if (nonce->nc >= digestConfig.noncemaxuses - 1) {
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
static AuthUser *
authDigestUserFindUsername(const char *username)
{
    AuthUserHashPointer *usernamehash;
    AuthUser *auth_user;
    debugs(29, 9, HERE << "Looking for user '" << username << "'");

    if (username && (usernamehash = static_cast < auth_user_hash_pointer * >(hash_lookup(proxy_auth_username_cache, username)))) {
        while ((usernamehash->user()->auth_type != AUTH_DIGEST) &&
                (usernamehash->next))
            usernamehash = static_cast < auth_user_hash_pointer * >(usernamehash->next);

        auth_user = NULL;

        if (usernamehash->user()->auth_type == AUTH_DIGEST) {
            auth_user = usernamehash->user();
        }

        return auth_user;
    }

    return NULL;
}

static void
authDigestUserShutdown(void)
{
    /** \todo Future work: the auth framework could flush it's cache */
    AuthUserHashPointer *usernamehash;
    AuthUser *auth_user;
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((auth_user_hash_pointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();

        if (strcmp(auth_user->config->type(), "digest") == 0)
            auth_user->unlock();
    }
}

/** delete the digest request structure. Does NOT delete related structures */
void
digestScheme::done()
{
    /** \todo this should be a Config call. */

    if (digestauthenticators)
        helperShutdown(digestauthenticators);

    authdigest_initialised = 0;

    if (!shutting_down) {
        authenticateDigestNonceReconfigure();
        return;
    }

    if (digestauthenticators) {
        helperFree(digestauthenticators);
        digestauthenticators = NULL;
    }

    authDigestUserShutdown();
    authenticateDigestNonceShutdown();
    debugs(29, 2, "authenticateDigestDone: Digest authentication shut down.");
}

void
AuthDigestConfig::dump(StoreEntry * entry, const char *name, AuthConfig * scheme)
{
    wordlist *list = authenticate;
    debugs(29, 9, "authDigestCfgDump: Dumping configuration");
    storeAppendPrintf(entry, "%s %s", name, "digest");

    while (list != NULL) {
        storeAppendPrintf(entry, " %s", list->key);
        list = list->next;
    }

    storeAppendPrintf(entry, "\n%s %s realm %s\n%s %s children %d\n%s %s nonce_max_count %d\n%s %s nonce_max_duration %d seconds\n%s %s nonce_garbage_interval %d seconds\n",
                      name, "digest", digestAuthRealm,
                      name, "digest", authenticateChildren,
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
    if ((authenticate != NULL) &&
            (authenticateChildren != 0) &&
            (digestAuthRealm != NULL) && (noncemaxduration > -1))
        return true;

    return false;
}

int
AuthDigestUserRequest::authenticated() const
{
    if (credentials() == Ok)
        return 1;

    return 0;
}

/** log a digest user in
 */
void
AuthDigestUserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
{
    AuthUser *auth_user;
    AuthDigestUserRequest *digest_request;
    digest_user_h *digest_user;

    HASHHEX SESSIONKEY;
    HASHHEX HA2 = "";
    HASHHEX Response;

    assert(authUser() != NULL);
    auth_user = authUser();

    digest_user = dynamic_cast < digest_user_h * >(auth_user);

    assert(digest_user != NULL);

    /* if the check has corrupted the user, just return */

    if (credentials() == Failed) {
        return;
    }

    digest_request = this;

    /* do we have the HA1 */

    if (!digest_user->HA1created) {
        credentials(Pending);
        return;
    }

    if (digest_request->nonce == NULL) {
        /* this isn't a nonce we issued */
        credentials(Failed);
        return;
    }

    DigestCalcHA1(digest_request->algorithm, NULL, NULL, NULL,
                  authenticateDigestNonceNonceb64(digest_request->nonce),
                  digest_request->cnonce,
                  digest_user->HA1, SESSIONKEY);
    DigestCalcResponse(SESSIONKEY, authenticateDigestNonceNonceb64(digest_request->nonce),
                       digest_request->nc, digest_request->cnonce, digest_request->qop,
                       RequestMethodStr(request->method), digest_request->uri, HA2, Response);

    debugs(29, 9, "\nResponse = '" << digest_request->response << "'\nsquid is = '" << Response << "'");

    if (strcasecmp(digest_request->response, Response) != 0) {
        if (!digest_request->flags.helper_queried) {
            /* Query the helper in case the password has changed */
            digest_request->flags.helper_queried = 1;
            digest_request->credentials_ok = Pending;
            return;
        }

        if (digestConfig.PostWorkaround && request->method != METHOD_GET) {
            /* Ugly workaround for certain very broken browsers using the
             * wrong method to calculate the request-digest on POST request.
             * This should be deleted once Digest authentication becomes more
             * widespread and such broken browsers no longer are commonly
             * used.
             */
            DigestCalcResponse(SESSIONKEY, authenticateDigestNonceNonceb64(digest_request->nonce),
                               digest_request->nc, digest_request->cnonce, digest_request->qop,
                               RequestMethodStr(METHOD_GET), digest_request->uri, HA2, Response);

            if (strcasecmp(digest_request->response, Response)) {
                credentials(Failed);
                digest_request->setDenyMessage("Incorrect password");
                return;
            } else {
                const char *useragent = request->header.getStr(HDR_USER_AGENT);

                static IpAddress last_broken_addr;
                static int seen_broken_client = 0;

                if (!seen_broken_client) {
                    last_broken_addr.SetNoAddr();
                    seen_broken_client = 1;
                }

                if (last_broken_addr != request->client_addr) {
                    debugs(29, 1, "\nDigest POST bug detected from " <<
                           request->client_addr << " using '" <<
                           (useragent ? useragent : "-") <<
                           "'. Please upgrade browser. See Bug #630 for details.");

                    last_broken_addr = request->client_addr;
                }
            }
        } else {
            credentials(Failed);
            digest_request->flags.invalid_password = 1;
            digest_request->setDenyMessage("Incorrect password");
            return;
        }

        /* check for stale nonce */
        if (!authDigestNonceIsValid(digest_request->nonce, digest_request->nc)) {
            debugs(29, 3, "authenticateDigestAuthenticateuser: user '" << digest_user->username() << "' validated OK but nonce stale");
            credentials(Failed);
            digest_request->setDenyMessage("Stale nonce");
            return;
        }
    }

    credentials(Ok);

    /* password was checked and did match */
    debugs(29, 4, "authenticateDigestAuthenticateuser: user '" << digest_user->username() << "' validated OK");

    /* auth_user is now linked, we reset these values
     * after external auth occurs anyway */
    auth_user->expiretime = current_time.tv_sec;
    return;
}

int
AuthDigestUserRequest::module_direction()
{
    switch (credentials()) {

    case Unchecked:
        return -1;

    case Ok:

        return 0;

    case Pending:
        return -1;

    case Failed:

        /* send new challenge */
        return 1;
    }

    return -2;
}

/* add the [proxy]authorisation header */
void
AuthDigestUserRequest::addHeader(HttpReply * rep, int accel)
{
    http_hdr_type type;

    /* don't add to authentication error pages */

    if ((!accel && rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (accel && rep->sline.status == HTTP_UNAUTHORIZED))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

#if WAITING_FOR_TE
    /* test for http/1.1 transfer chunked encoding */
    if (chunkedtest)
        return;

#endif

    if ((digestConfig.authenticate) && authDigestNonceLastRequest(nonce)) {
        flags.authinfo_sent = 1;
        debugs(29, 9, "authDigestAddHead: Sending type:" << type << " header: 'nextnonce=\"" << authenticateDigestNonceNonceb64(nonce) << "\"");
        httpHeaderPutStrf(&rep->header, type, "nextnonce=\"%s\"", authenticateDigestNonceNonceb64(nonce));
    }
}

#if WAITING_FOR_TE
/* add the [proxy]authorisation header */
void
AuthDigestUserRequest::addTrailer(HttpReply * rep, int accel)
{
    int type;

    if (!auth_user_request)
        return;


    /* has the header already been send? */
    if (flags.authinfo_sent)
        return;

    /* don't add to authentication error pages */
    if ((!accel && rep->sline.status == HTTP_PROXY_AUTHENTICATION_REQUIRED)
            || (accel && rep->sline.status == HTTP_UNAUTHORIZED))
        return;

    type = accel ? HDR_AUTHENTICATION_INFO : HDR_PROXY_AUTHENTICATION_INFO;

    if ((digestConfig.authenticate) && authDigestNonceLastRequest(nonce)) {
        debugs(29, 9, "authDigestAddTrailer: Sending type:" << type << " header: 'nextnonce=\"" << authenticateDigestNonceNonceb64(nonce) << "\"");
        httpTrailerPutStrf(&rep->header, type, "nextnonce=\"%s\"", authenticateDigestNonceNonceb64(nonce));
    }
}

#endif

/* add the [www-|Proxy-]authenticate header on a 407 or 401 reply */
void
AuthDigestConfig::fixHeader(AuthUserRequest *auth_user_request, HttpReply *rep, http_hdr_type type, HttpRequest * request)
{
    if (!authenticate)
        return;

    int stale = 0;

    if (auth_user_request) {
        AuthDigestUserRequest *digest_request;
        digest_request = dynamic_cast < AuthDigestUserRequest * >(auth_user_request);
        assert (digest_request != NULL);

        stale = !digest_request->flags.invalid_password;
    }

    /* on a 407 or 401 we always use a new nonce */
    digest_nonce_h *nonce = authenticateDigestNonceNew();

    debugs(29, 9, "authenticateFixHeader: Sending type:" << type <<
           " header: 'Digest realm=\"" << digestAuthRealm << "\", nonce=\"" <<
           authenticateDigestNonceNonceb64(nonce) << "\", qop=\"" << QOP_AUTH <<
           "\", stale=" << (stale ? "true" : "false"));

    /* in the future, for WWW auth we may want to support the domain entry */
    httpHeaderPutStrf(&rep->header, type, "Digest realm=\"%s\", nonce=\"%s\", qop=\"%s\", stale=%s", digestAuthRealm, authenticateDigestNonceNonceb64(nonce), QOP_AUTH, stale ? "true" : "false");
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

static void
authenticateDigestHandleReply(void *data, char *reply)
{
    DigestAuthenticateStateData *replyData = static_cast < DigestAuthenticateStateData * >(data);
    AuthUserRequest *auth_user_request;
    AuthDigestUserRequest *digest_request;
    digest_user_h *digest_user;
    char *t = NULL;
    void *cbdata;
    debugs(29, 9, "authenticateDigestHandleReply: {" << (reply ? reply : "<NULL>") << "}");

    if (reply) {
        if ((t = strchr(reply, ' ')))
            *t++ = '\0';

        if (*reply == '\0' || *reply == '\n')
            reply = NULL;
    }

    assert(replyData->auth_user_request != NULL);
    auth_user_request = replyData->auth_user_request;
    digest_request = dynamic_cast < AuthDigestUserRequest * >(auth_user_request);
    assert(digest_request);

    digest_user = dynamic_cast < digest_user_h * >(auth_user_request->user());
    assert(digest_user != NULL);

    if (reply && (strncasecmp(reply, "ERR", 3) == 0)) {
        digest_request->credentials(AuthDigestUserRequest::Failed);
        digest_request->flags.invalid_password = 1;

        if (t && *t)
            digest_request->setDenyMessage(t);
    } else if (reply) {
        CvtBin(reply, digest_user->HA1);
        digest_user->HA1created = 1;
    }

    if (cbdataReferenceValidDone(replyData->data, &cbdata))
        replyData->handler(cbdata, NULL);

    //we know replyData->auth_user_request != NULL, or we'd have asserted
    AUTHUSERREQUESTUNLOCK(replyData->auth_user_request, "replyData");

    cbdataFree(replyData);
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
AuthDigestConfig::init(AuthConfig * scheme)
{
    if (authenticate) {
        authenticateDigestNonceSetup();
        authdigest_initialised = 1;

        if (digestauthenticators == NULL)
            digestauthenticators = helperCreate("digestauthenticator");

        digestauthenticators->cmdline = authenticate;

        digestauthenticators->n_to_start = authenticateChildren;

        digestauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(digestauthenticators);

        CBDATA_INIT_TYPE(DigestAuthenticateStateData);
    }
}

void
AuthDigestConfig::registerWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("digestauthenticator",
                   "Digest User Authenticator Stats",
                   authenticateDigestStats, 0, 1);
}

/* free any allocated configuration details */
void
AuthDigestConfig::done()
{
    if (authenticate)
        wordlistDestroy(&authenticate);

    safe_free(digestAuthRealm);
}


AuthDigestConfig::AuthDigestConfig()
{
    /* TODO: move into initialisation list */
    authenticateChildren = 5;
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
        if (authenticate)
            wordlistDestroy(&authenticate);

        parse_wordlist(&authenticate);

        requirePathnameExists("auth_param digest program", authenticate->key);
    } else if (strcasecmp(param_str, "children") == 0) {
        parse_int(&authenticateChildren);
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
    return digestScheme::GetInstance().type();
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
    digest_user_h *digest_user;
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
    digest_user_h *digest_user;

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
static AuthUserRequest *
authDigestLogUsername(char *username, AuthDigestUserRequest *auth_user_request)
{
    assert(auth_user_request != NULL);

    /* log the username */
    debugs(29, 9, "authDigestLogUsername: Creating new user for logging '" << username << "'");
    digest_user_h *digest_user = new DigestUser(&digestConfig);
    /* save the credentials */
    digest_user->username(username);
    /* set the auth_user type */
    digest_user->auth_type = AUTH_BROKEN;
    /* link the request to the user */
    auth_user_request->authUser(digest_user);
    auth_user_request->user(digest_user);
    digest_user->addRequest (auth_user_request);
    return auth_user_request;
}

/*
 * Decode a Digest [Proxy-]Auth string, placing the results in the passed
 * Auth_user structure.
 */
AuthUserRequest *
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
        if ((p = strchr(item, '=')) && (p - item < ilen))
            ilen = p++ - item;

        if (!strncmp(item, "username", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            /* quote mark */
            p++;

            safe_free(username);
            username = xstrndup(p, strchr(p, '"') + 1 - p);

            debugs(29, 9, "authDigestDecodeAuth: Found Username '" << username << "'");
        } else if (!strncmp(item, "realm", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            /* quote mark */
            p++;

            safe_free(digest_request->realm);
            digest_request->realm = xstrndup(p, strchr(p, '"') + 1 - p);

            debugs(29, 9, "authDigestDecodeAuth: Found realm '" << digest_request->realm << "'");
        } else if (!strncmp(item, "qop", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            if (*p == '\"')
                /* quote mark */
                p++;

            safe_free(digest_request->qop);
            digest_request->qop = xstrndup(p, strcspn(p, "\" \t\r\n()<>@,;:\\/[]?={}") + 1);

            debugs(29, 9, "authDigestDecodeAuth: Found qop '" << digest_request->qop << "'");
        } else if (!strncmp(item, "algorithm", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            if (*p == '\"')
                /* quote mark */
                p++;

            safe_free(digest_request->algorithm);
            digest_request->algorithm = xstrndup(p, strcspn(p, "\" \t\r\n()<>@,;:\\/[]?={}") + 1);

            debugs(29, 9, "authDigestDecodeAuth: Found algorithm '" << digest_request->algorithm << "'");
        } else if (!strncmp(item, "uri", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            /* quote mark */
            p++;

            safe_free(digest_request->uri);
            digest_request->uri = xstrndup(p, strchr(p, '"') + 1 - p);

            debugs(29, 9, "authDigestDecodeAuth: Found uri '" << digest_request->uri << "'");
        } else if (!strncmp(item, "nonce", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            /* quote mark */
            p++;

            safe_free(digest_request->nonceb64);
            digest_request->nonceb64 = xstrndup(p, strchr(p, '"') + 1 - p);

            debugs(29, 9, "authDigestDecodeAuth: Found nonce '" << digest_request->nonceb64 << "'");
        } else if (!strncmp(item, "nc", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            xstrncpy(digest_request->nc, p, 9);

            debugs(29, 9, "authDigestDecodeAuth: Found noncecount '" << digest_request->nc << "'");
        } else if (!strncmp(item, "cnonce", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            /* quote mark */
            p++;

            safe_free(digest_request->cnonce);
            digest_request->cnonce = xstrndup(p, strchr(p, '"') + 1 - p);

            debugs(29, 9, "authDigestDecodeAuth: Found cnonce '" << digest_request->cnonce << "'");
        } else if (!strncmp(item, "response", ilen)) {
            /* white space */

            while (xisspace(*p))
                p++;

            /* quote mark */
            p++;

            safe_free(digest_request->response);
            digest_request->response = xstrndup(p, strchr(p, '"') + 1 - p);

            debugs(29, 9, "authDigestDecodeAuth: Found response '" << digest_request->response << "'");
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

    /* first the NONCE count */

    if (digest_request->cnonce && strlen(digest_request->nc) != 8) {
        debugs(29, 4, "authenticateDigestDecode: nonce count length invalid");
        return authDigestLogUsername(username, digest_request);
    }

    /* now the nonce */
    nonce = authenticateDigestNonceFindNonce(digest_request->nonceb64);

    if (!nonce) {
        /* we couldn't find a matching nonce! */
        debugs(29, 4, "authenticateDigestDecode: Unexpected or invalid nonce received");
        return authDigestLogUsername(username, digest_request);
    }

    digest_request->nonce = nonce;
    authDigestNonceLink(nonce);

    /* check the qop is what we expected. Note that for compatability with
     * RFC 2069 we should support a missing qop. Tough. */

    if (digest_request->qop && strcmp(digest_request->qop, QOP_AUTH) != 0) {
        /* we received a qop option we didn't send */
        debugs(29, 4, "authenticateDigestDecode: Invalid qop option received");
        return authDigestLogUsername(username, digest_request);
    }

    /* we can't check the URI just yet. We'll check it in the
     * authenticate phase */

    /* is the response the correct length? */

    if (!digest_request->response || strlen(digest_request->response) != 32) {
        debugs(29, 4, "authenticateDigestDecode: Response length invalid");
        return authDigestLogUsername(username, digest_request);
    }

    /* do we have a username ? */
    if (!username || username[0] == '\0') {
        debugs(29, 4, "authenticateDigestDecode: Empty or not present username");
        return authDigestLogUsername(username, digest_request);
    }

    /* check that we're not being hacked / the username hasn't changed */
    if (nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 4, "authenticateDigestDecode: Username for the nonce does not equal the username for the request");
        return authDigestLogUsername(username, digest_request);
    }

    /* if we got a qop, did we get a cnonce or did we get a cnonce wihtout a qop? */
    if ((digest_request->qop && !digest_request->cnonce)
            || (!digest_request->qop && digest_request->cnonce)) {
        debugs(29, 4, "authenticateDigestDecode: qop without cnonce, or vice versa!");
        return authDigestLogUsername(username, digest_request);
    }

    /* check the algorithm is present and supported */
    if (!digest_request->algorithm)
        digest_request->algorithm = xstrndup("MD5", 4);
    else if (strcmp(digest_request->algorithm, "MD5")
             && strcmp(digest_request->algorithm, "MD5-sess")) {
        debugs(29, 4, "authenticateDigestDecode: invalid algorithm specified!");
        return authDigestLogUsername(username, digest_request);
    }

    /* the method we'll check at the authenticate step as well */


    /* we don't send or parse opaques. Ok so we're flexable ... */

    /* find the user */
    digest_user_h *digest_user;

    AuthUser *auth_user;

    if ((auth_user = authDigestUserFindUsername(username)) == NULL) {
        /* the user doesn't exist in the username cache yet */
        debugs(29, 9, "authDigestDecodeAuth: Creating new digest user '" << username << "'");
        digest_user = new DigestUser (&digestConfig);
        /* auth_user is a parent */
        auth_user = digest_user;
        /* save the username */
        digest_user->username(username);
        /* set the user type */
        digest_user->auth_type = AUTH_DIGEST;
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
        digest_user = static_cast < digest_user_h * >(auth_user);
        xfree(username);
    }

    /*link the request and the user */
    assert(digest_request != NULL);

    digest_request->authUser (digest_user);

    digest_request->user(digest_user);

    digest_user->addRequest (digest_request);

    debugs(29, 9, "username = '" << digest_user->username() << "'\nrealm = '" <<
           digest_request->realm << "'\nqop = '" << digest_request->qop <<
           "'\nalgorithm = '" << digest_request->algorithm << "'\nuri = '" <<
           digest_request->uri << "'\nnonce = '" << digest_request->nonceb64 <<
           "'\nnc = '" << digest_request->nc << "'\ncnonce = '" <<
           digest_request->cnonce << "'\nresponse = '" <<
           digest_request->response << "'\ndigestnonce = '" << nonce << "'");

    return digest_request;
}

/* send the initial data to a digest authenticator module */
void
AuthDigestUserRequest::module_start(RH * handler, void *data)
{
    DigestAuthenticateStateData *r = NULL;
    char buf[8192];
    digest_user_h *digest_user;
    assert(user()->auth_type == AUTH_DIGEST);
    digest_user = dynamic_cast < digest_user_h * >(user());
    assert(digest_user != NULL);
    debugs(29, 9, "authenticateStart: '\"" << digest_user->username() << "\":\"" << realm << "\"'");

    if (digestConfig.authenticate == NULL) {
        handler(data, NULL);
        return;
    }

    r = cbdataAlloc(DigestAuthenticateStateData);
    r->handler = handler;
    r->data = cbdataReference(data);
    r->auth_user_request = this;
    AUTHUSERREQUESTLOCK(r->auth_user_request, "r");
    if (digestConfig.utf8) {
        char user[1024];
        latin1_to_utf8(user, sizeof(user), digest_user->username());
        snprintf(buf, 8192, "\"%s\":\"%s\"\n", user, realm);
    } else {
        snprintf(buf, 8192, "\"%s\":\"%s\"\n", digest_user->username(), realm);
    }

    helperSubmit(digestauthenticators, buf, authenticateDigestHandleReply, r);
}

DigestUser::DigestUser (AuthConfig *config) : AuthUser (config), HA1created (0)
{}

AuthUser *
AuthDigestUserRequest::authUser() const
{
    return const_cast<AuthUser *>(user());
}

void
AuthDigestUserRequest::authUser(AuthUser *aUser)
{
    assert(!authUser());
    user(aUser);
    user()->lock();
}

AuthDigestUserRequest::CredentialsState
AuthDigestUserRequest::credentials() const
{
    return credentials_ok;
}

void
AuthDigestUserRequest::credentials(CredentialsState newCreds)
{
    credentials_ok = newCreds;
}

AuthDigestUserRequest::AuthDigestUserRequest() : nonceb64(NULL) ,cnonce(NULL) ,realm(NULL),
        pszPass(NULL) ,algorithm(NULL) ,pszMethod(NULL),
        qop(NULL) ,uri(NULL) ,response(NULL),
        nonce(NULL), _theUser (NULL) ,
        credentials_ok (Unchecked)
{}

/** delete the digest request structure. Does NOT delete related structures */
AuthDigestUserRequest::~AuthDigestUserRequest()
{
    safe_free (nonceb64);
    safe_free (cnonce);
    safe_free (realm);
    safe_free (pszPass);
    safe_free (algorithm);
    safe_free (pszMethod);
    safe_free (qop);
    safe_free (uri);
    safe_free (response);

    if (nonce)
        authDigestNonceUnlink(nonce);
}

AuthConfig *
digestScheme::createConfig()
{
    return &digestConfig;
}

