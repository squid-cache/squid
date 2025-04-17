/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_NEGOTIATE_USER_H
#define SQUID_SRC_AUTH_NEGOTIATE_USER_H

#if HAVE_AUTH_MODULE_NEGOTIATE

#include "auth/User.h"

namespace Auth
{

class SchemeConfig;

namespace Negotiate
{

/** User credentials for the Negotiate authentication protocol */
class User : public Auth::User
{
    MEMPROXY_CLASS(Auth::Negotiate::User);

public:
    User(Auth::SchemeConfig *, const char *requestRealm);
    ~User() override;
    int32_t ttl() const override;

    /* Auth::User API */
    static CbcPointer<Auth::CredentialsCache> Cache();
    void addToNameCache() override;

    dlink_list proxy_auth_list;
};

} // namespace Negotiate
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_NEGOTIATE */
#endif /* SQUID_SRC_AUTH_NEGOTIATE_USER_H */

