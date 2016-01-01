/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/digest/Config.h"
#include "auth/digest/Scheme.h"
#include "Debug.h"
#include "globals.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Digest::Scheme::_instance = NULL;

Auth::Scheme::Pointer
Auth::Digest::Scheme::GetInstance()
{
    if (_instance == NULL) {
        _instance = new Auth::Digest::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Digest::Scheme::type() const
{
    return "digest";
}

void
Auth::Digest::Scheme::shutdownCleanup()
{
    if (_instance == NULL)
        return;

    PurgeCredentialsCache();
    authenticateDigestNonceShutdown();

    _instance = NULL;
    debugs(29, DBG_CRITICAL, "Shutdown: Digest authentication.");
}

Auth::Config *
Auth::Digest::Scheme::createConfig()
{
    Auth::Digest::Config *digestCfg = new Auth::Digest::Config;
    return dynamic_cast<Auth::Config*>(digestCfg);
}

void
Auth::Digest::Scheme::PurgeCredentialsCache(void)
{
    AuthUserHashPointer *usernamehash;

    debugs(29, 2, HERE << "Erasing Digest authentication credentials from username cache.");
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = static_cast<AuthUserHashPointer *>(hash_next(proxy_auth_username_cache)) )) {
        Auth::User::Pointer auth_user = usernamehash->user();

        if (strcmp(auth_user->config->type(), "digest") == 0) {
            hash_remove_link(proxy_auth_username_cache, static_cast<hash_link*>(usernamehash));
            delete usernamehash;
        }
    }
}

