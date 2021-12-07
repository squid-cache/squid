/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_DIGEST_USER_H
#define _SQUID_AUTH_DIGEST_USER_H

#if HAVE_AUTH_MODULE_DIGEST

#include "auth/digest/Config.h"
#include "auth/User.h"
#include "rfc2617.h"

namespace Auth
{
namespace Digest
{

/** User credentials for the Digest authentication protocol */
class User : public Auth::User
{
    MEMPROXY_CLASS(Auth::Digest::User);

public:
    User(Auth::SchemeConfig *, const char *requestRealm);
    virtual ~User();
    int authenticated() const;
    virtual int32_t ttl() const override;

    /* Auth::User API */
    static CbcPointer<Auth::CredentialsCache> Cache();
    virtual void addToNameCache() override;

    HASH HA1;
    int HA1created;

    /* what nonces have been allocated to this user */
    dlink_list nonces;

    digest_nonce_h * currentNonce();
};

} // namespace Digest
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_DIGEST */
#endif /* _SQUID_AUTH_DIGEST_USER_H */

