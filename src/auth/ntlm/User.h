/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_NTLM_USER_H
#define _SQUID_AUTH_NTLM_USER_H

#if HAVE_AUTH_MODULE_NTLM

#include "auth/User.h"

namespace Auth
{

namespace Ntlm
{

/** User credentials for the NTLM authentication protocol */
class User : public Auth::User
{
    MEMPROXY_CLASS(Auth::Ntlm::User);

public:
    User(Auth::SchemeConfig *, const char *requestRealm);
    virtual ~User();
    virtual int32_t ttl() const override;

    /* Auth::User API */
    static CbcPointer<Auth::CredentialsCache> Cache();
    virtual void addToNameCache() override;

    dlink_list proxy_auth_list;
};

} // namespace Ntlm
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_NTLM */
#endif /* _SQUID_AUTH_NTLM_USER_H */

