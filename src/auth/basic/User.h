/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_BASIC_USER_H
#define SQUID_SRC_AUTH_BASIC_USER_H

#if HAVE_AUTH_MODULE_BASIC

#include "auth/User.h"
#include "auth/UserRequest.h"

namespace Auth
{

class SchemeConfig;
class QueueNode;

namespace Basic
{

/** User credentials for the Basic authentication protocol */
class User : public Auth::User
{
    MEMPROXY_CLASS(Auth::Basic::User);

public:
    User(Auth::SchemeConfig *, const char *requestRealm);
    ~User() override;
    bool authenticated() const;
    bool valid() const;

    /** Update the cached password for a username. */
    void updateCached(User *from);
    int32_t ttl() const override;

    /* Auth::User API */
    static CbcPointer<Auth::CredentialsCache> Cache();
    void addToNameCache() override;

    char *passwd;

    QueueNode *queue;

private:
    Auth::UserRequest::Pointer currentRequest;
};

} // namespace Basic
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BASIC */
#endif /* SQUID_SRC_AUTH_BASIC_USER_H */

