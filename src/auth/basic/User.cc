/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/basic/Config.h"
#include "auth/basic/User.h"
#include "auth/Config.h"
#include "auth/CredentialsCache.h"
#include "Debug.h"

Auth::Basic::User::User(Auth::SchemeConfig *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm),
    passwd(NULL),
    queue(NULL),
    currentRequest(NULL)
{}

Auth::Basic::User::~User()
{
    safe_free(passwd);
}

Auth::Ttl
Auth::Basic::User::ttl() const
{
    static const Auth::Ttl expired(-1);
    if (credentials() != Auth::Ok && credentials() != Auth::Pending)
        return expired;

    return Auth::Ttl(expiretime - current_time.tv_sec);
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
