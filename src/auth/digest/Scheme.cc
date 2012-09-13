/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
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
