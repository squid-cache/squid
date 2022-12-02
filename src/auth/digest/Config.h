/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef __AUTH_DIGEST_H__
#define __AUTH_DIGEST_H__

#if HAVE_AUTH_MODULE_DIGEST

#include "auth/Gadgets.h"
#include "auth/SchemeConfig.h"
#include "auth/UserRequest.h"
#include "base/RefCount.h"
#include "helper/forward.h"
#include "rfc2617.h"

namespace Auth
{
namespace Digest
{
class User;
}
}

/* the nonce structure we'll pass around */
class digest_nonce_h : public hash_link, public RefCountable
{
    MEMPROXY_CLASS(digest_nonce_h);

public:
    typedef RefCount<digest_nonce_h> Pointer;

    digest_nonce_h() = default;
    digest_nonce_h(const digest_nonce_h &) = delete; // non-copyable
    ~digest_nonce_h() { xfree(key); }

    /// The HEX encoded unique identifier for this nonce
    const char *hex() const { return static_cast<const char *>(key); }

    /// Check the nonce and invalidate if any tests fail.
    /// \retval true if the nonce is valid.
    bool valid(char clientCount[9]);

    /// Check the freshness of this nonce and invalidate if stale.
    /// \retval true if the nonce is stale.
    bool stale();

    /**
     * Try to predict what the nonce validity will be if used on the
     * next HTTP Request.
     *
     * \retval false when the nonce is not stale yet
     * \retval true if the nonce will be stale on the next request
     */
    bool lastRequest() const;

public:
    /* data to be encoded into the nonce's hex representation */
    struct _digest_nonce_data {
        time_t creationtime = 0;
        uint32_t randomdata = 0;
    } noncedata;

    /* number of uses we've seen of this nonce */
    unsigned long nc = 0;

    /* the auth_user this nonce has been tied to */
    Auth::Digest::User *user = nullptr;

    /* has this nonce been invalidated ? */
    struct {
        bool valid = true;
        bool incache = false;
    } flags;
};

void authDigestNonceUnlink(digest_nonce_h * nonce);
void authenticateDigestNonceShutdown(void);
void authDigestNoncePurge(digest_nonce_h * nonce);
void authDigestUserLinkNonce(Auth::Digest::User * user, digest_nonce_h * nonce);
digest_nonce_h *authenticateDigestNonceNew(void);

namespace Auth
{
namespace Digest
{

/** Digest Authentication configuration data */
class Config : public Auth::SchemeConfig
{
public:
    Config();
    virtual bool active() const;
    virtual bool configured() const;
    virtual Auth::UserRequest::Pointer decode(char const *proxy_auth, const HttpRequest *request, const char *requestRealm);
    virtual void done();
    virtual void rotateHelpers();
    virtual bool dump(StoreEntry *, const char *, Auth::SchemeConfig *) const;
    virtual void fixHeader(Auth::UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *);
    virtual void init(Auth::SchemeConfig *);
    virtual void parse(Auth::SchemeConfig *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;

public:
    time_t nonceGCInterval;
    time_t noncemaxduration;
    unsigned int noncemaxuses;
    int NonceStrictness;
    int CheckNonceCount;
    int PostWorkaround;
};

} // namespace Digest
} // namespace Auth

/* strings */
#define QOP_AUTH "auth"

extern helper *digestauthenticators;

#endif /* HAVE_AUTH_MODULE_DIGEST */
#endif

