/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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
#include "helper/forward.h"
#include "rfc2617.h"

namespace Auth
{
namespace Digest
{
class User;
}
}

/* Generic */
typedef struct _digest_nonce_data digest_nonce_data;
typedef struct _digest_nonce_h digest_nonce_h;

/* data to be encoded into the nonce's hex representation */
struct _digest_nonce_data {
    time_t creationtime;
    /* in memory address of the nonce struct (similar purpose to an ETag) */
    digest_nonce_h *self;
    uint32_t randomdata;
};

/* the nonce structure we'll pass around */

struct _digest_nonce_h : public hash_link {
    digest_nonce_data noncedata;
    /* number of uses we've seen of this nonce */
    unsigned long nc;
    /* reference count */
    short references;
    /* the auth_user this nonce has been tied to */
    Auth::Digest::User *user;
    /* has this nonce been invalidated ? */

    struct {
        bool valid;
        bool incache;
    } flags;
};

void authDigestNonceUnlink(digest_nonce_h * nonce);
int authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9]);
int authDigestNonceIsStale(digest_nonce_h * nonce);
const char *authenticateDigestNonceNonceHex(const digest_nonce_h * nonce);
int authDigestNonceLastRequest(digest_nonce_h * nonce);
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
    virtual Auth::UserRequest::Pointer decode(char const *proxy_auth, const char *requestRealm);
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

