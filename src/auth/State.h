/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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
    CBDATA_CLASS(StateData);

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
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* __AUTH_AUTHENTICATE_STATE_T__ */

