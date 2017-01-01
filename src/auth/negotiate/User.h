/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_NEGOTIATE_USER_H
#define _SQUID_AUTH_NEGOTIATE_USER_H

#include "auth/User.h"

namespace Auth
{

class Config;

namespace Negotiate
{

/** User credentials for the Negotiate authentication protocol */
class User : public Auth::User
{
public:
    MEMPROXY_CLASS(Auth::Negotiate::User);
    User(Auth::Config *, const char *requestRealm);
    ~User();
    virtual int32_t ttl() const;

    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(Auth::Negotiate::User);

} // namespace Negotiate
} // namespace Auth

#endif /* _SQUID_AUTH_NEGOTIATE_USER_H */

