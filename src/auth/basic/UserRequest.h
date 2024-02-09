/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_BASIC_USERREQUEST_H
#define SQUID_SRC_AUTH_BASIC_USERREQUEST_H

#if HAVE_AUTH_MODULE_BASIC

#include "auth/UserRequest.h"

class ConnStateData;
class HttpRequest;

namespace Auth
{

namespace Basic
{

/* follows the http request around */

class UserRequest : public Auth::UserRequest
{
    MEMPROXY_CLASS(Auth::Basic::UserRequest);

public:
    UserRequest() {}
    ~UserRequest() override { assert(LockCount()==0); }

    int authenticated() const override;
    void authenticate(HttpRequest * request, ConnStateData *conn, Http::HdrType type) override;
    Auth::Direction module_direction() override;
    void startHelperLookup(HttpRequest * request, AccessLogEntry::Pointer &al, AUTHCB *, void *) override;
    const char *credentialsStr() override;

private:
    static HLPCB HandleReply;
};

} // namespace Basic
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BASIC */
#endif /* SQUID_SRC_AUTH_BASIC_USERREQUEST_H */

