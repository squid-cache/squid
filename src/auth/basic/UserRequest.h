/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_BASIC_USERREQUEST_H
#define _SQUID_SRC_AUTH_BASIC_USERREQUEST_H

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
    virtual ~UserRequest() { assert(LockCount()==0); }

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData *conn, Http::HdrType type);
    virtual Auth::Direction module_direction();
    virtual void startHelperLookup(HttpRequest * request, AccessLogEntry::Pointer &al, AUTHCB *, void *);
    virtual const char *credentialsStr();

private:
    static HLPCB HandleReply;
};

} // namespace Basic
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BASIC */
#endif /* _SQUID_SRC_AUTH_BASIC_USERREQUEST_H */

