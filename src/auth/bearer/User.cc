/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/bearer/User.h"
#include "auth/bearer/UserRequest.h"
#include "auth/Config.h"
#include "auth/CredentialsCache.h"
#include "auth/QueueNode.h"

Auth::Bearer::User::User(SchemeConfig *aConfig, const char *aRequestRealm, const SBuf &tokenBlob) :
        Auth::User(aConfig, aRequestRealm),
        token(new Token(tokenBlob))
{
    token->user = this;
}

Auth::Bearer::User::~User()
{
    debugs(29, 5, "doing nothing to clear Bearer scheme data for " << this);
}

int32_t
Auth::Bearer::User::ttl() const
{
    // no token? should never happen, but treat as expired
    if (!token)
        return -1;

    // credentials expiry depends on the Token age.
    return static_cast<int32_t>(token->expires - squid_curtime);
}

CbcPointer<Auth::CredentialsCache>
Auth::Bearer::User::Cache()
{
    static CbcPointer<Auth::CredentialsCache> p(new Auth::CredentialsCache("bearer", "GC Bearer user credentials"));
    return p;
}

void
Auth::Bearer::User::addToNameCache()
{
    Cache()->insert(userKey(), this);
}
