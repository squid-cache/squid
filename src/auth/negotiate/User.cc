/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/Config.h"
#include "auth/negotiate/User.h"
#include "auth/UserNameCache.h"
#include "Debug.h"

Auth::Negotiate::User::User(Auth::Config *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm)
{
}

Auth::Negotiate::User::~User()
{
    debugs(29, 5, HERE << "doing nothing to clear Negotiate scheme data for '" << this << "'");
}

int32_t
Auth::Negotiate::User::ttl() const
{
    return -1; // Negotiate cannot be cached.
}

CbcPointer<Auth::UserNameCache>
Auth::Negotiate::User::Cache()
{
    static CbcPointer<Auth::UserNameCache> p(new Auth::UserNameCache("negotiate"));
    return p;
}

void
Auth::Negotiate::User::addToNameCache()
{
    Cache()->insert(this);
}

