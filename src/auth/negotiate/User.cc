/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/CredentialsCache.h"
#include "auth/negotiate/User.h"
#include "auth/SchemeConfig.h"
#include "debug/Stream.h"

Auth::Negotiate::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm)
{
}

Auth::Negotiate::User::~User()
{
    debugs(29, 5, "doing nothing to clear Negotiate scheme data for '" << this << "'");
}

int32_t
Auth::Negotiate::User::ttl() const
{
    return -1; // Negotiate cannot be cached.
}

CbcPointer<Auth::CredentialsCache>
Auth::Negotiate::User::Cache()
{
    static CbcPointer<Auth::CredentialsCache> p(new Auth::CredentialsCache("negotiate", "GC Negotiate user credentials"));
    return p;
}

void
Auth::Negotiate::User::addToNameCache()
{
    Cache()->insert(userKey(), this);
}

