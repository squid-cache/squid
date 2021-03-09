/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/CredentialsCache.h"
#include "auth/ntlm/User.h"
#include "auth/SchemeConfig.h"
#include "Debug.h"

Auth::Ntlm::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm)
{
}

Auth::Ntlm::User::~User()
{
    debugs(29, 5, HERE << "doing nothing to clear NTLM scheme data for '" << this << "'");
}

Auth::Ttl
Auth::Ntlm::User::ttl() const
{
    static const Auth::Ttl expired(-1);
    return expired; // NTLM credentials cannot be cached.
}

CbcPointer<Auth::CredentialsCache>
Auth::Ntlm::User::Cache()
{
    static CbcPointer<Auth::CredentialsCache> p(new Auth::CredentialsCache("ntlm", "GC NTLM user credentials"));
    return p;
}

void
Auth::Ntlm::User::addToNameCache()
{
    Cache()->insert(userKey(), this);
}

