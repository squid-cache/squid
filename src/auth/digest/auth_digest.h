/*
 * auth_digest.h
 * Internal declarations for the digest auth module
 */

#ifndef __AUTH_DIGEST_H__
#define __AUTH_DIGEST_H__
#include "rfc2617.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "auth/Config.h"
#include "helper.h"

/* Generic */

class DigestAuthenticateStateData
{

public:
    void *data;
    AuthUserRequest *auth_user_request;
    RH *handler;
};

typedef struct _digest_nonce_data digest_nonce_data;

typedef struct _digest_nonce_h digest_nonce_h;

class DigestUser : public AuthUser
{

public:
    MEMPROXY_CLASS(DigestUser);

    DigestUser(AuthConfig *);
    ~DigestUser();
    int authenticated() const;
    HASH HA1;
    int HA1created;

    /* what nonces have been allocated to this user */
    dlink_list nonces;

};

MEMPROXY_CLASS_INLINE(DigestUser);

typedef class DigestUser digest_user_h;

/* the digest_request structure is what follows the http_request around */

class AuthDigestUserRequest : public AuthUserRequest
{

public:
    enum CredentialsState {Unchecked, Ok, Pending, Failed};
    MEMPROXY_CLASS(AuthDigestUserRequest);

    AuthDigestUserRequest();
    virtual ~AuthDigestUserRequest();

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type);
    virtual int module_direction();
    virtual void addHeader(HttpReply * rep, int accel);
#if WAITING_FOR_TE

    virtual void addTrailer(HttpReply * rep, int accel);
#endif

    virtual void module_start(RH *, void *);
    virtual AuthUser *user() {return _theUser;}

    virtual const AuthUser *user() const {return _theUser;}

    virtual void user(AuthUser *aUser) {_theUser=dynamic_cast<DigestUser *>(aUser);}

    CredentialsState credentials() const;
    void credentials(CredentialsState);

    void authUser(AuthUser *);
    AuthUser *authUser() const;

    char *nonceb64;		/* "dcd98b7102dd2f0e8b11d0f600bfb0c093" */
    char *cnonce;		/* "0a4f113b" */
    char *realm;		/* = "testrealm@host.com" */
    char *pszPass;		/* = "Circle Of Life" */
    char *algorithm;		/* = "md5" */
    char nc[9];			/* = "00000001" */
    char *pszMethod;		/* = "GET" */
    char *qop;			/* = "auth" */
    char *uri;			/* = "/dir/index.html" */
    char *response;

    struct {
        unsigned int authinfo_sent:1;
        unsigned int invalid_password:1;
        unsigned int helper_queried:1;
    } flags;
    digest_nonce_h *nonce;

private:
    DigestUser *_theUser;
    CredentialsState credentials_ok;
};

MEMPROXY_CLASS_INLINE(AuthDigestUserRequest);

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

/* configuration runtime data */

class AuthDigestConfig : public AuthConfig
{

public:
    AuthDigestConfig();
    virtual bool active() const;
    virtual bool configured() const;
    virtual AuthUserRequest *decode(char const *proxy_auth);
    virtual void done();
    virtual void dump(StoreEntry *, const char *, AuthConfig *);
    virtual void fixHeader(AuthUserRequest *, HttpReply *, http_hdr_type, HttpRequest *);
    virtual void init(AuthConfig *);
    virtual void parse(AuthConfig *, int, char *);
    virtual void registerWithCacheManager(void);
    virtual const char * type() const;
    int authenticateChildren;
    char *digestAuthRealm;
    wordlist *authenticate;
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

#endif
