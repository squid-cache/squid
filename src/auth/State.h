#ifndef __AUTH_AUTHENTICATE_STATE_T__
#define __AUTH_AUTHENTICATE_STATE_T__

#if USE_AUTH

#include "auth/UserRequest.h"
#include "cbdata.h"

namespace Auth
{

/**
 * CBDATA state for NTLM, Negotiate, and Digest stateful authentication.
 */
class StateData
{
public:
    StateData(const UserRequest::Pointer &r, AUTHCB *h, void *d) :
            data(cbdataReference(d)),
            auth_user_request(r),
            handler(h) {}

    ~StateData() {
        auth_user_request = NULL;
        cbdataReferenceDone(data);
    }

    void *data;
    UserRequest::Pointer auth_user_request;
    AUTHCB *handler;

private:
    CBDATA_CLASS2(StateData);
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* __AUTH_AUTHENTICATE_STATE_T__ */
