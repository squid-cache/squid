#ifndef __AUTH_AUTHENTICATE_STATE_T__
#define __AUTH_AUTHENTICATE_STATE_T__

#if USE_AUTH

#include "auth/UserRequest.h"

/**
 * CBDATA state for NTLM, Negotiate, and Digest stateful authentication.
 */
typedef struct {
    void *data;
    AuthUserRequest::Pointer auth_user_request;
    RH *handler;
} authenticateStateData;

extern CBDATA_GLOBAL_TYPE(authenticateStateData);

extern void authenticateStateFree(authenticateStateData * r);

#endif /* USE_AUTH */
#endif /* __AUTH_AUTHENTICATE_STATE_T__ */
