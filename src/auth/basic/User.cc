/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/basic/Config.h"
#include "auth/basic/User.h"
#include "auth/CredentialsCache.h"
#include "Debug.h"
#include "SquidConfig.h"
#include "SquidTime.h"

Auth::Basic::User::User(Auth::Config *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm),
    passwd(NULL),
    queue(NULL),
    currentRequest(NULL)
{}

Auth::Basic::User::~User()
{
    safe_free(passwd);
}

int32_t
Auth::Basic::User::ttl() const
{
    if (credentials() != Auth::Ok && credentials() != Auth::Pending)
        return -1; // TTL is obsolete NOW.

    int32_t basic_ttl = expiretime - squid_curtime + static_cast<Auth::Basic::Config*>(config)->credentialsTTL;
    int32_t global_ttl = static_cast<int32_t>(expiretime - squid_curtime + ::Config.authenticateTTL);

    return min(basic_ttl, global_ttl);
}

bool
Auth::Basic::User::authenticated() const
{
    if ((credentials() == Auth::Ok) && (expiretime + static_cast<Auth::Basic::Config*>(config)->credentialsTTL > squid_curtime))
        return true;

    debugs(29, 4, "User not authenticated or credentials need rechecking.");

    return false;
}

bool
Auth::Basic::User::valid() const
{
    if (username() == NULL)
        return false;
    if (passwd == NULL)
        return false;
    return true;
}

void
Auth::Basic::User::updateCached(Auth::Basic::User *from)
{
    debugs(29, 9, HERE << "Found user '" << from->username() << "' already in the user cache as '" << this << "'");

    assert(strcmp(from->username(), username()) == 0);

    if (strcmp(from->passwd, passwd)) {
        debugs(29, 4, HERE << "new password found. Updating in user master record and resetting auth state to unchecked");
        credentials(Auth::Unchecked);
        xfree(passwd);
        passwd = from->passwd;
        from->passwd = NULL;
    }

    if (credentials() == Auth::Failed) {
        debugs(29, 4, HERE << "last attempt to authenticate this user failed, resetting auth state to unchecked");
        credentials(Auth::Unchecked);
    }
}

CbcPointer<Auth::CredentialsCache>
Auth::Basic::User::Cache()
{
    static CbcPointer<Auth::CredentialsCache> p(new Auth::CredentialsCache("basic", "GC Basic user credentials"));
    return p;
}

void
Auth::Basic::User::addToNameCache()
{
    Cache()->insert(userKey(), this);
}

