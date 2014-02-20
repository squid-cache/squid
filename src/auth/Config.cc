/*
 * DEBUG: section 29    Authenticator
 * AUTHOR:  Robert Collins
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
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/UserRequest.h"
#include "Debug.h"
#include "globals.h"

Auth::ConfigVector Auth::TheConfig;

/**
 * Get an User credentials object filled out for the given Proxy- or WWW-Authenticate header.
 * Any decoding which needs to be done will be done.
 *
 * It may be a cached AuthUser or a new Unauthenticated object.
 * It may also be NULL reflecting that no user could be created.
 */
Auth::UserRequest::Pointer
Auth::Config::CreateAuthUser(const char *proxy_auth)
{
    assert(proxy_auth != NULL);
    debugs(29, 9, HERE << "header = '" << proxy_auth << "'");

    Auth::Config *config = Find(proxy_auth);

    if (config == NULL || !config->active()) {
        debugs(29, (shutting_down?3:DBG_IMPORTANT), (shutting_down?"":"WARNING: ") <<
               "Unsupported or unconfigured/inactive proxy-auth scheme, '" << proxy_auth << "'");
        return NULL;
    }

    return config->decode(proxy_auth);
}

Auth::Config *
Auth::Config::Find(const char *proxy_auth)
{
    for (Auth::ConfigVector::iterator  i = Auth::TheConfig.begin(); i != Auth::TheConfig.end(); ++i)
        if (strncasecmp(proxy_auth, (*i)->type(), strlen((*i)->type())) == 0)
            return *i;

    return NULL;
}

/** Default behaviour is to expose nothing */
void
Auth::Config::registerWithCacheManager(void)
{}

Auth::User::Pointer
Auth::Config::findUserInCache(const char *nameKey, Auth::Type authType)
{
    AuthUserHashPointer *usernamehash;
    debugs(29, 9, "Looking for user '" << nameKey << "'");

    if (nameKey && (usernamehash = static_cast<AuthUserHashPointer *>(hash_lookup(proxy_auth_username_cache, nameKey)))) {
        while (usernamehash) {
            if ((usernamehash->user()->auth_type == authType) &&
                    !strcmp(nameKey, (char const *)usernamehash->key))
                return usernamehash->user();

            usernamehash = static_cast<AuthUserHashPointer *>(usernamehash->next);
        }
    }

    return NULL;
}
