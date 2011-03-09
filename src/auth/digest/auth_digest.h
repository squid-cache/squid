/*
 * auth_digest.h
 * Internal declarations for the digest auth module
 */

#ifndef __AUTH_DIGEST_H__
#define __AUTH_DIGEST_H__

#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "helper.h"
#include "rfc2617.h"

/* Generic */

typedef struct _digest_nonce_data digest_nonce_data;

typedef struct _digest_nonce_h digest_nonce_h;

class DigestUser : public AuthUser
{

public:
    MEMPROXY_CLASS(DigestUser);

    DigestUser(AuthConfig *);
    ~DigestUser();
    int authenticated() const;

    virtual int32_t ttl() const;

    HASH HA1;
    int HA1created;

    /* what nonces have been allocated to this user */
    dlink_list nonces;

};

MEMPROXY_CLASS_INLINE(DigestUser);


/* data to be encoded into the nonce's b64 representation */

struct _digest_nonce_data {
    time_t creationtime;
    /* in memory address of the nonce struct (similar purpose to an ETag) */
    digest_nonce_h *self;
    long randomdata;
};

/* the nonce structure we'll pass around */

struct _digest_nonce_h : public hash_link {
    digest_nonce_data noncedata;
    /* number of uses we've seen of this nonce */
    unsigned long nc;
    /* reference count */
    short references;
    /* the auth_user this nonce has been tied to */
    DigestUser *user;
    /* has this nonce been invalidated ? */

    struct {
        unsigned int valid:1;
        unsigned int incache:1;
    } flags;
};

extern void authDigestNonceUnlink(digest_nonce_h * nonce);
extern int authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9]);
extern const char *authenticateDigestNonceNonceb64(const digest_nonce_h * nonce);
extern int authDigestNonceLastRequest(digest_nonce_h * nonce);

/* configuration runtime data */

class AuthDigestConfig : public AuthConfig
{

public:
    AuthDigestConfig();
    virtual bool active() const;
    virtual bool configured() const;
    virtual AuthUserRequest::Pointer decode(char const *proxy_auth);
    virtual void done();
    virtual void rotateHelpers();
    virtual void dump(StoreEntry *, const char *, AuthConfig *);
    virtual void fixHeader(AuthUserRequest::Pointer, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(AuthConfig *);
    virtual void parse(AuthConfig *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;
    char *digestAuthRealm;
    time_t nonceGCInterval;
    time_t noncemaxduration;
    unsigned int noncemaxuses;
    int NonceStrictness;
    int CheckNonceCount;
    int PostWorkaround;
    int utf8;
};

typedef class AuthDigestConfig auth_digest_config;

/* strings */
#define QOP_AUTH "auth"

extern helper *digestauthenticators;

#endif
