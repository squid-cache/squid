/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_DIGEST_CONFIG_H
#define SQUID_SRC_AUTH_DIGEST_CONFIG_H

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
    uint32_t randomdata;
};

/* the nonce structure we'll pass around */

struct _digest_nonce_h : public hash_link {
    digest_nonce_data noncedata;
    /* number of uses we've seen of this nonce */
    unsigned long nc;
    /* reference count */
    uint64_t references;
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
    bool active() const override;
    bool configured() const override;
    Auth::UserRequest::Pointer decode(char const *proxy_auth, const HttpRequest *request, const char *requestRealm) override;
    void done() override;
    void rotateHelpers() override;
    bool dump(StoreEntry *, const char *, Auth::SchemeConfig *) const override;
    void fixHeader(Auth::UserRequest::Pointer, HttpReply *, Http::HdrType, HttpRequest *) override;
    void init(Auth::SchemeConfig *) override;
    void parse(Auth::SchemeConfig *, int, char *) override;
    void registerWithCacheManager(void) override;
    const char * type() const override;

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
#endif /* SQUID_SRC_AUTH_DIGEST_CONFIG_H */

