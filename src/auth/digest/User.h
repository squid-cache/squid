/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_DIGEST_USER_H
#define _SQUID_AUTH_DIGEST_USER_H

#include "auth/User.h"

namespace Auth
{
namespace Digest
{

/** User credentials for the Digest authentication protocol */
class User : public Auth::User
{
public:
    MEMPROXY_CLASS(Auth::Digest::User);

    User(Auth::Config *, const char *requestRealm);
    ~User();
    int authenticated() const;

    virtual int32_t ttl() const;

    HASH HA1;
    int HA1created;

    /* what nonces have been allocated to this user */
    dlink_list nonces;

    digest_nonce_h * currentNonce();
};

MEMPROXY_CLASS_INLINE(Auth::Digest::User);

} // namespace Digest
} // namespace Auth

#endif /* _SQUID_AUTH_DIGEST_USER_H */

