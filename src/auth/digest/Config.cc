/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "auth/CredentialsCache.h"
#include "auth/digest/Config.h"
#include "auth/digest/Scheme.h"
#include "auth/digest/User.h"
#include "auth/digest/UserRequest.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "auth/toUtf.h"
#include "base/LookupTable.h"
#include "cache_cf.h"
#include "event.h"
#include "helper.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "md5.h"
#include "mgr/Registration.h"
#include "rfc2617.h"
#include "sbuf/SBuf.h"
#include "sbuf/StringConvert.h"
#include "SquidTime.h"
#include "Store.h"
#include "StrList.h"
#include "wordlist.h"

/* digest_nonce_h still uses explicit alloc()/freeOne() MemPool calls.
 * XXX: convert to MEMPROXY_CLASS() API
 */
#include "mem/Pool.h"

#include <random>

static AUTHSSTATS authenticateDigestStats;

helper *digestauthenticators = NULL;

static hash_table *digest_nonce_cache;

static int authdigest_initialised = 0;
static MemAllocator *digest_nonce_pool = NULL;

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
    DIGEST_INVALID_ATTR
};

static const LookupTable<http_digest_attr_type>::Record
DigestAttrs[] = {
    {"username", DIGEST_USERNAME},
    {"realm", DIGEST_REALM},
    {"qop", DIGEST_QOP},
    {"algorithm", DIGEST_ALGORITHM},
    {"uri", DIGEST_URI},
    {"nonce", DIGEST_NONCE},
    {"nc", DIGEST_NC},
    {"cnonce", DIGEST_CNONCE},
    {"response", DIGEST_RESPONSE},
    {nullptr, DIGEST_INVALID_ATTR}
};

LookupTable<http_digest_attr_type>
DigestFieldsLookupTable(DIGEST_INVALID_ATTR, DigestAttrs);

/*
 *
 * Nonce Functions
 *
 */

static void authenticateDigestNonceCacheCleanup(void *data);
static digest_nonce_h *authenticateDigestNonceFindNonce(const char *noncehex);
static void authenticateDigestNonceDelete(digest_nonce_h * nonce);
static void authenticateDigestNonceSetup(void);
static void authDigestNonceEncode(digest_nonce_h * nonce);
static void authDigestNonceLink(digest_nonce_h * nonce);
static void authDigestNonceUserUnlink(digest_nonce_h * nonce);

static void
authDigestNonceEncode(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (nonce->key)
        xfree(nonce->key);

    SquidMD5_CTX Md5Ctx;
    HASH H;
    SquidMD5Init(&Md5Ctx);
    SquidMD5Update(&Md5Ctx, reinterpret_cast<const uint8_t *>(&nonce->noncedata), sizeof(nonce->noncedata));
    SquidMD5Final(reinterpret_cast<uint8_t *>(H), &Md5Ctx);

    nonce->key = xcalloc(sizeof(HASHHEX), 1);
    CvtHex(H, static_cast<char *>(nonce->key));
}

digest_nonce_h *
authenticateDigestNonceNew(void)
{
    digest_nonce_h *newnonce = static_cast < digest_nonce_h * >(digest_nonce_pool->alloc());

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
     * nonces stored. If we send out unique encodings we guarantee
     * that a given nonce applies to only one user (barring attacks or
     * really bad timing with expiry and creation).  Using a random
     * component in the nonce allows us to loop to find a unique nonce.
     * We use H(nonce_data) so the nonce is meaningless to the reciever.
     * So our nonce looks like hex(H(timestamp,randomdata))
     * And even if our randomness is not very random we don't really care
     * - the timestamp also guarantees local uniqueness in the input to
     * the hash function.
     */
    // NP: this will likely produce the same randomness sequences for each worker
    // since they should all start within the 1-second resolution of seed value.
    static std::mt19937 mt(static_cast<uint32_t>(getCurrentTime() & 0xFFFFFFFF));
    static xuniform_int_distribution<uint32_t> newRandomData;

    /* create a new nonce */
    newnonce->nc = 0;
    newnonce->flags.valid = true;
    newnonce->noncedata.creationtime = current_time.tv_sec;
    newnonce->noncedata.randomdata = newRandomData(mt);

    authDigestNonceEncode(newnonce);

    // ensure temporal uniqueness by checking for existing nonce
    while (authenticateDigestNonceFindNonce((char const *) (newnonce->key))) {
        /* create a new nonce */
        newnonce->noncedata.randomdata = newRandomData(mt);
        authDigestNonceEncode(newnonce);
    }

    hash_join(digest_nonce_cache, newnonce);
    /* the cache's link */
    authDigestNonceLink(newnonce);
    newnonce->flags.incache = true;
    debugs(29, 5, "created nonce " << newnonce << " at " << newnonce->noncedata.creationtime);
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

        assert(!nonce->flags.incache);

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
        eventAdd("Digest nonce cache maintenance", authenticateDigestNonceCacheCleanup, NULL, static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->nonceGCInterval, 1);
    }
}

void
authenticateDigestNonceShutdown(void)
{
    /*
     * We empty the cache of any nonces left in there.
     */
    digest_nonce_h *nonce;

    if (digest_nonce_cache) {
        debugs(29, 2, "Shutting down nonce cache");
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
    debugs(29, 2, "Nonce cache shutdown");
}

static void
authenticateDigestNonceCacheCleanup(void *)
{
    /*
     * We walk the hash by noncehex as that is the unique key we
     * use.  For big hash tables we could consider stepping through
     * the cache, 100/200 entries at a time. Lets see how it flies
     * first.
     */
    digest_nonce_h *nonce;
    debugs(29, 3, "Cleaning the nonce cache now");
    debugs(29, 3, "Current time: " << current_time.tv_sec);
    hash_first(digest_nonce_cache);

    while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
        debugs(29, 3, "nonce entry  : " << nonce << " '" << (char *) nonce->key << "'");
        debugs(29, 4, "Creation time: " << nonce->noncedata.creationtime);

        if (authDigestNonceIsStale(nonce)) {
            debugs(29, 4, "Removing nonce " << (char *) nonce->key << " from cache due to timeout.");
            assert(nonce->flags.incache);
            /* invalidate nonce so future requests fail */
            nonce->flags.valid = false;
            /* if it is tied to a auth_user, remove the tie */
            authDigestNonceUserUnlink(nonce);
            authDigestNoncePurge(nonce);
        }
    }

    debugs(29, 3, "Finished cleaning the nonce cache.");

    if (static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->active())
        eventAdd("Digest nonce cache maintenance", authenticateDigestNonceCacheCleanup, NULL, static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->nonceGCInterval, 1);
}

static void
authDigestNonceLink(digest_nonce_h * nonce)
{
    assert(nonce != NULL);
    ++nonce->references;
    assert(nonce->references != 0); // no overflows
    debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");
}

void
authDigestNonceUnlink(digest_nonce_h * nonce)
{
    assert(nonce != NULL);

    if (nonce->references > 0) {
        -- nonce->references;
    } else {
        debugs(29, DBG_IMPORTANT, "Attempt to lower nonce " << nonce << " refcount below 0!");
    }

    debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");

    if (nonce->references == 0)
        authenticateDigestNonceDelete(nonce);
}

const char *
authenticateDigestNonceNonceHex(const digest_nonce_h * nonce)
{
    if (!nonce)
        return NULL;

    return (char const *) nonce->key;
}

static digest_nonce_h *
authenticateDigestNonceFindNonce(const char *noncehex)
{
    digest_nonce_h *nonce = NULL;

    if (noncehex == NULL)
        return NULL;

    debugs(29, 9, "looking for noncehex '" << noncehex << "' in the nonce cache.");

    nonce = static_cast < digest_nonce_h * >(hash_lookup(digest_nonce_cache, noncehex));

    if ((nonce == NULL) || (strcmp(authenticateDigestNonceNonceHex(nonce), noncehex)))
        return NULL;

    debugs(29, 9, "Found nonce '" << nonce << "'");

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
        debugs(29, 4, "Nonce already invalidated");
        return 0;
    }

    /* is the nonce-count ok ? */
    if (!static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->CheckNonceCount) {
        /* Ignore client supplied NC */
        intnc = nonce->nc + 1;
    }

    if ((static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->NonceStrictness && intnc != nonce->nc + 1) ||
            intnc < nonce->nc + 1) {
        debugs(29, 4, "Nonce count doesn't match");
        nonce->flags.valid = false;
        return 0;
    }

    /* increment the nonce count - we've already checked that intnc is a
     *  valid representation for us, so we don't need the test here.
     */
    nonce->nc = intnc;

    return !authDigestNonceIsStale(nonce);
}

int
authDigestNonceIsStale(digest_nonce_h * nonce)
{
    /* do we have a nonce ? */

    if (!nonce)
        return -1;

    /* Is it already invalidated? */
    if (!nonce->flags.valid)
        return -1;

    /* has it's max duration expired? */
    if (nonce->noncedata.creationtime + static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxduration < current_time.tv_sec) {
        debugs(29, 4, "Nonce is too old. " <<
               nonce->noncedata.creationtime << " " <<
               static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxduration << " " <<
               current_time.tv_sec);

        nonce->flags.valid = false;
        return -1;
    }

    if (nonce->nc > 99999998) {
        debugs(29, 4, "Nonce count overflow");
        nonce->flags.valid = false;
        return -1;
    }

    if (nonce->nc > static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxuses) {
        debugs(29, 4, "Nonce count over user limit");
        nonce->flags.valid = false;
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
        debugs(29, 4, "Nonce count about to overflow");
        return -1;
    }

    if (nonce->nc >= static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest"))->noncemaxuses - 1) {
        debugs(29, 4, "Nonce count about to hit user limit");
        return -1;
    }

    /* and other tests are possible. */
    return 0;
}

void
authDigestNoncePurge(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (!nonce->flags.incache)
        return;

    hash_remove_link(digest_nonce_cache, nonce);

    nonce->flags.incache = false;

    /* the cache's link */
    authDigestNonceUnlink(nonce);
}

void
Auth::Digest::Config::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (digestauthenticators) {
        helperShutdown(digestauthenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

bool
Auth::Digest::Config::dump(StoreEntry * entry, const char *name, Auth::SchemeConfig * scheme) const
{
    if (!Auth::SchemeConfig::dump(entry, name, scheme))
        return false;

    storeAppendPrintf(entry, "%s %s nonce_max_count %d\n%s %s nonce_max_duration %d seconds\n%s %s nonce_garbage_interval %d seconds\n",
                      name, "digest", noncemaxuses,
                      name, "digest", (int) noncemaxduration,
                      name, "digest", (int) nonceGCInterval);
    return true;
}

bool
Auth::Digest::Config::active() const
{
    return authdigest_initialised == 1;
}

bool
Auth::Digest::Config::configured() const
{
    if ((authenticateProgram != NULL) &&
            (authenticateChildren.n_max != 0) &&
            !realm.isEmpty() && (noncemaxduration > -1))
        return true;

    return false;
}

/* add the [www-|Proxy-]authenticate header on a 407 or 401 reply */
void
Auth::Digest::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, Http::HdrType hdrType, HttpRequest *)
{
    if (!authenticateProgram)
        return;

    bool stale = false;
    digest_nonce_h *nonce = NULL;

    /* on a 407 or 401 we always use a new nonce */
    if (auth_user_request != NULL) {
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(auth_user_request->user().getRaw());

        if (digest_user) {
            stale = digest_user->credentials() == Auth::Handshake;
            if (stale) {
                nonce = digest_user->currentNonce();
            }
        }
    }
    if (!nonce) {
        nonce = authenticateDigestNonceNew();
    }

    debugs(29, 9, "Sending type:" << hdrType <<
           " header: 'Digest realm=\"" << realm << "\", nonce=\"" <<
           authenticateDigestNonceNonceHex(nonce) << "\", qop=\"" << QOP_AUTH <<
           "\", stale=" << (stale ? "true" : "false"));

    /* in the future, for WWW auth we may want to support the domain entry */
    httpHeaderPutStrf(&rep->header, hdrType, "Digest realm=\"" SQUIDSBUFPH "\", nonce=\"%s\", qop=\"%s\", stale=%s",
                      SQUIDSBUFPRINT(realm), authenticateDigestNonceNonceHex(nonce), QOP_AUTH, stale ? "true" : "false");
}

/* Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
Auth::Digest::Config::init(Auth::SchemeConfig *)
{
    if (authenticateProgram) {
        authenticateDigestNonceSetup();
        authdigest_initialised = 1;

        if (digestauthenticators == NULL)
            digestauthenticators = new helper("digestauthenticator");

        digestauthenticators->cmdline = authenticateProgram;

        digestauthenticators->childs.updateLimits(authenticateChildren);

        digestauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(digestauthenticators);
    }
}

void
Auth::Digest::Config::registerWithCacheManager(void)
{
    Mgr::RegisterAction("digestauthenticator",
                        "Digest User Authenticator Stats",
                        authenticateDigestStats, 0, 1);
}

/* free any allocated configuration details */
void
Auth::Digest::Config::done()
{
    Auth::SchemeConfig::done();

    authdigest_initialised = 0;

    if (digestauthenticators)
        helperShutdown(digestauthenticators);

    if (!shutting_down)
        return;

    delete digestauthenticators;
    digestauthenticators = NULL;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);
}

Auth::Digest::Config::Config() :
    nonceGCInterval(5*60),
    noncemaxduration(30*60),
    noncemaxuses(50),
    NonceStrictness(0),
    CheckNonceCount(1),
    PostWorkaround(0)
{}

void
Auth::Digest::Config::parse(Auth::SchemeConfig * scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "nonce_garbage_interval") == 0) {
        parse_time_t(&nonceGCInterval);
    } else if (strcmp(param_str, "nonce_max_duration") == 0) {
        parse_time_t(&noncemaxduration);
    } else if (strcmp(param_str, "nonce_max_count") == 0) {
        parse_int((int *) &noncemaxuses);
    } else if (strcmp(param_str, "nonce_strictness") == 0) {
        parse_onoff(&NonceStrictness);
    } else if (strcmp(param_str, "check_nonce_count") == 0) {
        parse_onoff(&CheckNonceCount);
    } else if (strcmp(param_str, "post_workaround") == 0) {
        parse_onoff(&PostWorkaround);
    } else
        Auth::SchemeConfig::parse(scheme, n_configured, param_str);
}

const char *
Auth::Digest::Config::type() const
{
    return Auth::Digest::Scheme::GetInstance()->type();
}

static void
authenticateDigestStats(StoreEntry * sentry)
{
    if (digestauthenticators)
        digestauthenticators->packStatsInto(sentry, "Digest Authenticator Statistics");
}

/* NonceUserUnlink: remove the reference to auth_user and unlink the node from the list */

static void
authDigestNonceUserUnlink(digest_nonce_h * nonce)
{
    Auth::Digest::User *digest_user;
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
            delete tmplink;
            link = NULL;
        }
    }

    /* this reference to user was not locked because freeeing the user frees
     * the nonce too.
     */
    nonce->user = NULL;
}

/* authDigesteserLinkNonce: add a nonce to a given user's struct */
void
authDigestUserLinkNonce(Auth::Digest::User * user, digest_nonce_h * nonce)
{
    dlink_node *node;

    if (!user || !nonce || !nonce->user)
        return;

    Auth::Digest::User *digest_user = user;

    node = digest_user->nonces.head;

    while (node && (node->data != nonce))
        node = node->next;

    if (node)
        return;

    node = new dlink_node;

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
static Auth::UserRequest::Pointer
authDigestLogUsername(char *username, Auth::UserRequest::Pointer auth_user_request, const char *requestRealm)
{
    assert(auth_user_request != NULL);

    /* log the username */
    debugs(29, 9, "Creating new user for logging '" << (username?username:"[no username]") << "'");
    Auth::User::Pointer digest_user = new Auth::Digest::User(static_cast<Auth::Digest::Config*>(Auth::SchemeConfig::Find("digest")), requestRealm);
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
Auth::UserRequest::Pointer
Auth::Digest::Config::decode(char const *proxy_auth, const HttpRequest *request, const char *aRequestRealm)
{
    const char *item;
    const char *p;
    const char *pos = NULL;
    char *username = NULL;
    digest_nonce_h *nonce;
    int ilen;

    debugs(29, 9, "beginning");

    Auth::Digest::UserRequest *digest_request = new Auth::Digest::UserRequest();

    /* trim DIGEST from string */

    while (xisgraph(*proxy_auth))
        ++proxy_auth;

    /* Trim leading whitespace before decoding */
    while (xisspace(*proxy_auth))
        ++proxy_auth;

    String temp(proxy_auth);

    while (strListGetItem(&temp, ',', &item, &ilen, &pos)) {
        /* isolate directive name & value */
        size_t nlen;
        size_t vlen;
        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen)) {
            nlen = p - item;
            ++p;
            vlen = ilen - (p - item);
        } else {
            nlen = ilen;
            vlen = 0;
        }

        SBuf keyName(item, nlen);
        String value;

        if (vlen > 0) {
            // see RFC 2617 section 3.2.1 and 3.2.2 for details on the BNF

            if (keyName == SBuf("domain",6) || keyName == SBuf("uri",3)) {
                // domain is Special. Not a quoted-string, must not be de-quoted. But is wrapped in '"'
                // BUG 3077: uri= can also be sent to us in a mangled (invalid!) form like domain
                if (vlen > 1 && *p == '"' && *(p + vlen -1) == '"') {
                    value.assign(p+1, vlen-2);
                }
            } else if (keyName == SBuf("qop",3)) {
                // qop is more special.
                // On request this must not be quoted-string de-quoted. But is several values wrapped in '"'
                // On response this is a single un-quoted token.
                if (vlen > 1 && *p == '"' && *(p + vlen -1) == '"') {
                    value.assign(p+1, vlen-2);
                } else {
                    value.assign(p, vlen);
                }
            } else if (*p == '"') {
                if (!httpHeaderParseQuotedString(p, vlen, &value)) {
                    debugs(29, 9, "Failed to parse attribute '" << item << "' in '" << temp << "'");
                    continue;
                }
            } else {
                value.assign(p, vlen);
            }
        } else {
            debugs(29, 9, "Failed to parse attribute '" << item << "' in '" << temp << "'");
            continue;
        }

        /* find type */
        const http_digest_attr_type t = DigestFieldsLookupTable.lookup(keyName);

        switch (t) {
        case DIGEST_USERNAME:
            safe_free(username);
            if (value.size() != 0) {
                const auto v = value.termedBuf();
                if (utf8 && !isValidUtf8String(v, v + value.size())) {
                    auto str = isCP1251EncodingAllowed(request) ? Cp1251ToUtf8(v) : Latin1ToUtf8(v);
                    value = SBufToString(str);
                }
                username = xstrndup(value.rawBuf(), value.size() + 1);
            }
            debugs(29, 9, "Found Username '" << username << "'");
            break;

        case DIGEST_REALM:
            safe_free(digest_request->realm);
            if (value.size() != 0)
                digest_request->realm = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found realm '" << digest_request->realm << "'");
            break;

        case DIGEST_QOP:
            safe_free(digest_request->qop);
            if (value.size() != 0)
                digest_request->qop = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found qop '" << digest_request->qop << "'");
            break;

        case DIGEST_ALGORITHM:
            safe_free(digest_request->algorithm);
            if (value.size() != 0)
                digest_request->algorithm = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found algorithm '" << digest_request->algorithm << "'");
            break;

        case DIGEST_URI:
            safe_free(digest_request->uri);
            if (value.size() != 0)
                digest_request->uri = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found uri '" << digest_request->uri << "'");
            break;

        case DIGEST_NONCE:
            safe_free(digest_request->noncehex);
            if (value.size() != 0)
                digest_request->noncehex = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found nonce '" << digest_request->noncehex << "'");
            break;

        case DIGEST_NC:
            if (value.size() != 8) {
                debugs(29, 9, "Invalid nc '" << value << "' in '" << temp << "'");
            }
            xstrncpy(digest_request->nc, value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found noncecount '" << digest_request->nc << "'");
            break;

        case DIGEST_CNONCE:
            safe_free(digest_request->cnonce);
            if (value.size() != 0)
                digest_request->cnonce = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found cnonce '" << digest_request->cnonce << "'");
            break;

        case DIGEST_RESPONSE:
            safe_free(digest_request->response);
            if (value.size() != 0)
                digest_request->response = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found response '" << digest_request->response << "'");
            break;

        default:
            debugs(29, 3, "Unknown attribute '" << item << "' in '" << temp << "'");
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

    // return value.
    Auth::UserRequest::Pointer rv;
    /* do we have a username ? */
    if (!username || username[0] == '\0') {
        debugs(29, 2, "Empty or not present username");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* Sanity check of the username.
     * " can not be allowed in usernames until * the digest helper protocol
     * have been redone
     */
    if (strchr(username, '"')) {
        debugs(29, 2, "Unacceptable username '" << username << "'");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* do we have a realm ? */
    if (!digest_request->realm || digest_request->realm[0] == '\0') {
        debugs(29, 2, "Empty or not present realm");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* and a nonce? */
    if (!digest_request->noncehex || digest_request->noncehex[0] == '\0') {
        debugs(29, 2, "Empty or not present nonce");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* we can't check the URI just yet. We'll check it in the
     * authenticate phase, but needs to be given */
    if (!digest_request->uri || digest_request->uri[0] == '\0') {
        debugs(29, 2, "Missing URI field");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* is the response the correct length? */
    if (!digest_request->response || strlen(digest_request->response) != 32) {
        debugs(29, 2, "Response length invalid");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* check the algorithm is present and supported */
    if (!digest_request->algorithm)
        digest_request->algorithm = xstrndup("MD5", 4);
    else if (strcmp(digest_request->algorithm, "MD5")
             && strcmp(digest_request->algorithm, "MD5-sess")) {
        debugs(29, 2, "invalid algorithm specified!");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* 2617 requirements, indicated by qop */
    if (digest_request->qop) {

        /* check the qop is what we expected. */
        if (strcmp(digest_request->qop, QOP_AUTH) != 0) {
            /* we received a qop option we didn't send */
            debugs(29, 2, "Invalid qop option received");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }

        /* check cnonce */
        if (!digest_request->cnonce || digest_request->cnonce[0] == '\0') {
            debugs(29, 2, "Missing cnonce field");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }

        /* check nc */
        if (strlen(digest_request->nc) != 8 || strspn(digest_request->nc, "0123456789abcdefABCDEF") != 8) {
            debugs(29, 2, "invalid nonce count");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }
    } else {
        /* cnonce and nc both require qop */
        if (digest_request->cnonce || digest_request->nc[0] != '\0') {
            debugs(29, 2, "missing qop!");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }
    }

    /** below nonce state dependent **/

    /* now the nonce */
    nonce = authenticateDigestNonceFindNonce(digest_request->noncehex);
    /* check that we're not being hacked / the username hasn't changed */
    if (nonce && nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "Username for the nonce does not equal the username for the request");
        nonce = NULL;
    }

    if (!nonce) {
        /* we couldn't find a matching nonce! */
        debugs(29, 2, "Unexpected or invalid nonce received from " << username);
        Auth::UserRequest::Pointer auth_request = authDigestLogUsername(username, digest_request, aRequestRealm);
        auth_request->user()->credentials(Auth::Handshake);
        safe_free(username);
        return auth_request;
    }

    digest_request->nonce = nonce;
    authDigestNonceLink(nonce);

    /* check that we're not being hacked / the username hasn't changed */
    if (nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "Username for the nonce does not equal the username for the request");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    /* the method we'll check at the authenticate step as well */

    /* we don't send or parse opaques. Ok so we're flexable ... */

    /* find the user */
    Auth::Digest::User *digest_user;

    Auth::User::Pointer auth_user;

    SBuf key = Auth::User::BuildUserKey(username, aRequestRealm);
    if (key.isEmpty() || !(auth_user = Auth::Digest::User::Cache()->lookup(key))) {
        /* the user doesn't exist in the username cache yet */
        debugs(29, 9, "Creating new digest user '" << username << "'");
        digest_user = new Auth::Digest::User(this, aRequestRealm);
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

        /* auth_user is now linked, we reset these values
         * after external auth occurs anyway */
        auth_user->expiretime = current_time.tv_sec;
    } else {
        debugs(29, 9, "Found user '" << username << "' in the user cache as '" << auth_user << "'");
        digest_user = static_cast<Auth::Digest::User *>(auth_user.getRaw());
        digest_user->credentials(Auth::Unchecked);
        xfree(username);
    }

    /*link the request and the user */
    assert(digest_request != NULL);

    digest_request->user(digest_user);
    debugs(29, 9, "username = '" << digest_user->username() << "'\nrealm = '" <<
           digest_request->realm << "'\nqop = '" << digest_request->qop <<
           "'\nalgorithm = '" << digest_request->algorithm << "'\nuri = '" <<
           digest_request->uri << "'\nnonce = '" << digest_request->noncehex <<
           "'\nnc = '" << digest_request->nc << "'\ncnonce = '" <<
           digest_request->cnonce << "'\nresponse = '" <<
           digest_request->response << "'\ndigestnonce = '" << nonce << "'");

    return digest_request;
}

