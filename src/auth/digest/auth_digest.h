/*
 * auth_digest.h
 * Internal declarations for the digest auth module
 */

#ifndef __AUTH_DIGEST_H__
#define __AUTH_DIGEST_H__
#include "rfc2617.h"
#include "authenticate.h"
/* Generic */

class DigestAuthenticateStateData
{

public:
    void *data;
    auth_user_request_t *auth_user_request;
    RH *handler;
};

typedef struct _digest_nonce_data digest_nonce_data;

typedef struct _digest_nonce_h digest_nonce_h;

class digest_user_h
{

public:
    void *operator new(size_t);
    void operator delete (void *);
    void deleteSelf() const;

    digest_user_h();
    ~digest_user_h();
    int authenticated() const;
    char *username;
    HASH HA1;
    int HA1created;

    /* what nonces have been allocated to this user */
    dlink_list nonces;

private:
    static MemPool *Pool;
};

/* the digest_request structure is what follows the http_request around */

class digest_request_h : public AuthUserRequestState
{

public:
    enum CredentialsState {Unchecked, Ok, Pending, Failed};
    void *operator new(size_t);
    void operator delete (void *);
    void deleteSelf() const;

    digest_request_h();
    digest_request_h(auth_user_t *);
    ~digest_request_h();

    int authenticated() const;
    virtual void authenticate(request_t * request, ConnStateData * conn, http_hdr_type type);
    virtual int direction();
    virtual void addHeader(HttpReply * rep, int accel);

    CredentialsState credentials() const;
    void credentials(CredentialsState);

    void authUser(auth_user_t *);
    auth_user_t *authUser() const;

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

    struct
    {

unsigned int authinfo_sent:
        1;
    }

    flags;
    digest_nonce_h *nonce;
    auth_user_t *theUser;

private:
    static MemPool *Pool;
    CredentialsState credentials_ok;
};

/* data to be encoded into the nonce's b64 representation */

struct _digest_nonce_data
{
    time_t creationtime;
    /* in memory address of the nonce struct (similar purpose to an ETag) */
    digest_nonce_h *self;
    long randomdata;
};

/* the nonce structure we'll pass around */

struct _digest_nonce_h : public hash_link
{
    digest_nonce_data noncedata;
    /* number of uses we've seen of this nonce */
    unsigned long nc;
    /* reference count */
    short references;
    /* the auth_user this nonce has been tied to */
    auth_user_t *auth_user;
    /* has this nonce been invalidated ? */

    struct
    {

unsigned int valid:
        1;

unsigned int incache:
        1;
    }

    flags;
};

/* configuration runtime data */

struct _auth_digest_config
{
    int authenticateChildren;
    char *digestAuthRealm;
    wordlist *authenticate;
    time_t nonceGCInterval;
    time_t noncemaxduration;
    unsigned int noncemaxuses;
    int NonceStrictness;
};

typedef struct _auth_digest_config auth_digest_config;

/* strings */
#define QOP_AUTH "auth"

#endif
