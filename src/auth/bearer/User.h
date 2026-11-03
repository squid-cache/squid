/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_BEARER_USER_H
#define _SQUID_AUTH_BEARER_USER_H

#if HAVE_AUTH_MODULE_BEARER

#include "auth/bearer/Token.h"
#include "auth/User.h"

namespace Auth
{

class QueueNode;

namespace Bearer
{

/// User credentials for the Bearer authentication protocol
class User : public Auth::User
{
    MEMPROXY_CLASS(Auth::Bearer::User);

public:
    User(SchemeConfig *, const char *requestRealm, const SBuf &tokenBlob);
    ~User();

    /* Auth::User API */
    virtual int32_t ttl() const override;
    static CbcPointer<Auth::CredentialsCache> Cache();
    virtual void addToNameCache() override;

    /// authentication attempts waiting on helper feedback
    QueueNode *queue = nullptr;

    /// the token used to create this User object
    TokenPointer token;
};

} // namespace Bearer
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BEARER */
#endif /* _SQUID_AUTH_BEARER_USER_H */
