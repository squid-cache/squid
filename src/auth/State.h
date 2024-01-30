/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_STATE_H
#define SQUID_SRC_AUTH_STATE_H

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
        auth_user_request = nullptr;
        cbdataReferenceDone(data);
    }

    void *data;
    UserRequest::Pointer auth_user_request;
    AUTHCB *handler;
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_STATE_H */

