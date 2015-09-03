/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/Config.h"
#include "auth/ntlm/User.h"
#include "auth/UserNameCache.h"
#include "Debug.h"

Auth::Ntlm::User::User(Auth::Config *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm)
{
    Cache()->insert(Pointer(this));
}

Auth::Ntlm::User::~User()
{
    debugs(29, 5, HERE << "doing nothing to clear NTLM scheme data for '" << this << "'");
}

int32_t
Auth::Ntlm::User::ttl() const
{
    return -1; // NTLM credentials cannot be cached.
}

CbcPointer<Auth::UserNameCache>
Auth::Ntlm::User::Cache()
{
    static CbcPointer<Auth::UserNameCache> p(new Auth::UserNameCache("basic"));
    return p;
}
