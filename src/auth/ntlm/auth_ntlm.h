/*
 * auth_ntlm.h
 * Internal declarations for the ntlm auth module
 */

#ifndef __AUTH_NTLM_H__
#define __AUTH_NTLM_H__

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

typedef enum {
    AUTHENTICATE_STATE_NONE,
    AUTHENTICATE_STATE_NEGOTIATE,
    AUTHENTICATE_STATE_CHALLENGE,
    AUTHENTICATE_STATE_RESPONSE,
    AUTHENTICATE_STATE_DONE,
    AUTHENTICATE_STATE_FAILED
} auth_state_t;                 /* connection level auth state */

/* Generic */
typedef struct {
    void *data;
    auth_user_request_t *auth_user_request;
    RH *handler;
} authenticateStateData;

struct _ntlm_user {
    /* what username did this connection get? */
    char *username;
    dlink_list proxy_auth_list;
};

struct _ntlm_request {
    /* what negotiate string did the client use? */
    char *ntlmnegotiate;
    /* what challenge did we give the client? */
    char *authchallenge;
    /* what authenticate string did we get? */
    char *ntlmauthenticate;
    /*we need to store the NTLM server between requests */
    helper_stateful_server *authserver;
    /* how far through the authentication process are we? */
    auth_state_t auth_state;
    /* have we got the helper-server in a deferred state? */
    int authserver_deferred;
    /* what connection is this associated with */
    ConnStateData *conn;
};

struct _ntlm_helper_state_t {
    char *challenge;		/* the challenge to use with this helper */
    int starve;			/* 0= normal operation. 1=don't hand out any more challenges */
    int challengeuses;		/* the number of times this challenge has been issued */
    time_t renewed;
};

/* configuration runtime data */
struct _auth_ntlm_config {
    int authenticateChildren;
    wordlist *authenticate;
    int challengeuses;
    time_t challengelifetime;
};

typedef struct _ntlm_user ntlm_user_t;
typedef struct _ntlm_request ntlm_request_t;
typedef struct _ntlm_helper_state_t ntlm_helper_state_t;
typedef struct _auth_ntlm_config auth_ntlm_config;

extern MemPool *ntlm_helper_state_pool;
extern MemPool *ntlm_user_pool;
extern MemPool *ntlm_request_pool;

#endif
