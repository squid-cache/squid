/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_NTLM_USER_H
#define _SQUID_AUTH_NTLM_USER_H

#include "auth/User.h"

namespace Auth
{

class Config;

namespace Ntlm
{

/** User credentials for the NTLM authentication protocol */
class User : public Auth::User
{
public:
    MEMPROXY_CLASS(Auth::Ntlm::User);
    User(Auth::Config *, const char *requestRealm);
    ~User();

    virtual int32_t ttl() const;

    dlink_list proxy_auth_list;
};

MEMPROXY_CLASS_INLINE(Auth::Ntlm::User);

} // namespace Ntlm
} // namespace Auth

#endif /* _SQUID_AUTH_NTLM_USER_H */

