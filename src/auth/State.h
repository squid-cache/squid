#ifndef __AUTH_AUTHENTICATE_STATE_T__
#define __AUTH_AUTHENTICATE_STATE_T__

#include "auth/UserRequest.h"

typedef enum {
    AUTHENTICATE_STATE_NONE,
    AUTHENTICATE_STATE_INITIAL,
    AUTHENTICATE_STATE_IN_PROGRESS,
    AUTHENTICATE_STATE_DONE,
    AUTHENTICATE_STATE_FAILED
} auth_state_t;                 /* connection level auth state */

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

#endif /* __AUTH_AUTHENTICATE_STATE_T__ */
