/*
 * $Id$
 *
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

#include "config.h"
#include "auth/digest/Scheme.h"
#include "helper.h"

AuthScheme::Pointer
digestScheme::GetInstance()
{
    if (_instance == NULL) {
        _instance = new digestScheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
digestScheme::type () const
{
    return "digest";
}

AuthScheme::Pointer digestScheme::_instance = NULL;

AuthConfig *
digestScheme::createConfig()
{
    AuthDigestConfig *digestCfg = new AuthDigestConfig;
    return dynamic_cast<AuthConfig*>(digestCfg);
}

void
digestScheme::PurgeCredentialsCache(void)
{
    AuthUserHashPointer *usernamehash;
    AuthUser::Pointer auth_user;
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = static_cast<AuthUserHashPointer *>(hash_next(proxy_auth_username_cache)) )) {
        auth_user = usernamehash->user();

        if (strcmp(auth_user->config->type(), "digest") == 0) {
            hash_remove_link(proxy_auth_username_cache, static_cast<hash_link*>(usernamehash));
            delete usernamehash;
        }
    }
}
