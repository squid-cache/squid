/*
 * auth_basic.h
 * Internal declarations for the basic auth module
 */

#ifndef __AUTH_BASIC_H__
#define __AUTH_BASIC_H__
#include "authenticate.h"

#define DefaultAuthenticateChildrenMax  32	/* 32 processes */

/* Generic */

class AuthenticateStateData
{

public:
    void *data;
    auth_user_request_t *auth_user_request;
    RH *handler;
};

/* queue of auth requests waiting for verification to occur */

class BasicAuthQueueNode
{

public:
    BasicAuthQueueNode *next;
    AuthUserRequest *auth_user_request;
    RH *handler;
    void *data;
};

class basic_data
{

public:
    char *username;
    char *passwd;
    time_t credentials_checkedtime;

    struct
    {

unsigned int credentials_ok:
        2;	/*0=unchecked,1=ok,2=failed */
    }

    flags;
    BasicAuthQueueNode *auth_queue;
};

/* configuration runtime data */

class auth_basic_config
{

public:
    int authenticateChildren;
    int authenticateConcurrency;
    char *basicAuthRealm;
    wordlist *authenticate;
    time_t credentialsTTL;
};

#endif
