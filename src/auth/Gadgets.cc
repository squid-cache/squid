/*
 * $Id$
 *
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

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "auth/Config.h"
#include "auth/Scheme.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "auth/AclProxyAuth.h"
#include "HttpReply.h"
#include "HttpRequest.h"

/**** PUBLIC FUNCTIONS (ALL GENERIC!)  ****/

int
authenticateActiveSchemeCount(void)
{
    int rv = 0;

    for (Auth::authConfig::iterator i = Auth::TheConfig.begin(); i != Auth::TheConfig.end(); ++i)
        if ((*i)->configured())
            ++rv;

    debugs(29, 9, "authenticateActiveSchemeCount: " << rv << " active.");

    return rv;
}

int
authenticateSchemeCount(void)
{
    int rv = AuthScheme::GetSchemes().size();

    debugs(29, 9, "authenticateSchemeCount: " << rv << " active.");

    return rv;
}

static void
authenticateRegisterWithCacheManager(Auth::authConfig * config)
{
    for (Auth::authConfig::iterator i = config->begin(); i != config->end(); ++i) {
        AuthConfig *scheme = *i;
        scheme->registerWithCacheManager();
    }
}

void
authenticateInit(Auth::authConfig * config)
{
    if (!config)
        return;

    for (Auth::authConfig::iterator i = config->begin(); i != config->end(); ++i) {
        AuthConfig *schemeCfg = *i;

        if (schemeCfg->configured())
            schemeCfg->init(schemeCfg);
    }

    if (!proxy_auth_username_cache)
        AuthUser::cacheInit();
    else
        AuthUser::CachedACLsReset();

    authenticateRegisterWithCacheManager(config);
}

void
authenticateShutdown(void)
{
    debugs(29, 2, "authenticateShutdown: shutting down auth schemes");
    /* free the cache if we are shutting down */

    if (shutting_down) {
        hashFreeItems(proxy_auth_username_cache, AuthUserHashPointer::removeFromCache);
        AuthScheme::FreeAll();
    } else {
        for (AuthScheme::iterator i = (AuthScheme::GetSchemes()).begin(); i != (AuthScheme::GetSchemes()).end(); ++i)
            (*i)->done();
    }
}

/**
 * Cleans all config-dependent data from the auth_user cache.
 \note It DOES NOT Flush the user cache.
 */
void
authenticateUserCacheRestart(void)
{
    AuthUserHashPointer *usernamehash;
    AuthUser::Pointer auth_user;
    debugs(29, 3, HERE << "Clearing config dependent cache data.");
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        debugs(29, 5, "authenticateUserCacheRestat: Clearing cache ACL results for user: " << auth_user->username());
    }
}

// TODO: remove this wrapper. inline the actions.
void
AuthUserHashPointer::removeFromCache(void *usernamehash_p)
{
    AuthUserHashPointer *usernamehash = static_cast<AuthUserHashPointer *>(usernamehash_p);
    hash_remove_link(proxy_auth_username_cache, (hash_link *)usernamehash);
    delete usernamehash;
}

AuthUserHashPointer::AuthUserHashPointer(AuthUser::Pointer anAuth_user):
        auth_user(anAuth_user)
{
    key = (void *)anAuth_user->username();
    next = NULL;
    hash_join(proxy_auth_username_cache, (hash_link *) this);
}

AuthUser::Pointer
AuthUserHashPointer::user() const
{
    return auth_user;
}
