/*
 * auth_basic.h
 * Internal declarations for the basic auth module
 */

#ifndef __AUTH_BASIC_H__
#define __AUTH_BASIC_H__


#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

/* Generic */
typedef struct {
    void *data;
    auth_user_request_t *auth_user_request;
    RH *handler;
} authenticateStateData;

typedef struct _auth_basic_queue_node auth_basic_queue_node;

/* queue of auth requests waiting for verification to occur */
struct _auth_basic_queue_node {
    auth_basic_queue_node *next;
    auth_user_request_t *auth_user_request;
    RH *handler;
    void *data;
};

struct _basic_data {
    char *username;
    char *passwd;
    time_t credentials_checkedtime;
    struct {
	unsigned int credentials_ok:2;	/*0=unchecked,1=ok,2=failed */
    } flags;
    auth_basic_queue_node *auth_queue;
};

/* configuration runtime data */
struct _auth_basic_config {
    int authenticateChildren;
    char *basicAuthRealm;
    wordlist *authenticate;
    time_t credentialsTTL;
};

typedef struct _auth_basic_config auth_basic_config;

typedef struct _basic_data basic_data;


#endif
