/*
 * auth_digest.h
 * Internal declarations for the digest auth module
 */

#ifndef __AUTH_DIGEST_H__
#define __AUTH_DIGEST_H__
#include "rfc2617.h"

/* Generic */
typedef struct {
    void *data;
    auth_user_request_t *auth_user_request;
    RH *handler;
} authenticateStateData;

typedef struct _digest_request_h digest_request_h;
typedef struct _digest_user_h digest_user_h;
typedef struct _digest_nonce_data digest_nonce_data;

typedef struct _digest_nonce_h digest_nonce_h;

struct _digest_user_h {
    char *username;
    HASH HA1;
    int HA1created;
    struct {
        unsigned int credentials_ok:2;  /*0=unchecked,1=ok,2=failed */
    } flags;
    /* what nonces have been allocated to this user */
    dlink_list nonces;
};

/* the digest_request structure is what follows the http_request around */
struct _digest_request_h {
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
    } flags;
    digest_nonce_h *nonce;
};

/* data to be encoded into the nonce's b64 representation */
struct _digest_nonce_data {
    time_t creationtime;
    /* in memory address of the nonce struct (similar purpose to an ETag) */
    digest_nonce_h *self;
    long randomdata;
};

/* the nonce structure we'll pass around */
struct _digest_nonce_h {
    hash_link hash;	/* must be first */
    digest_nonce_data noncedata;
    /* number of uses we've seen of this nonce */
    long nc;
    /* reference count */
    short references;
    /* the auth_user this nonce has been tied to */
    auth_user_t *auth_user;
    /* has this nonce been invalidated ? */
    struct {
	unsigned int valid:1;
	unsigned int incache:1;
    } flags;
};

/* configuration runtime data */
struct _auth_digest_config {
    int authenticateChildren;
    char *digestAuthRealm;
    wordlist *authenticate;
    time_t nonceGCInterval;
    time_t noncemaxduration;
    int noncemaxuses;
};

typedef struct _auth_digest_config auth_digest_config;

/* strings */
#define QOP_AUTH "auth"

#endif
