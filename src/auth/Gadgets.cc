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
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"

/**** PUBLIC FUNCTIONS (ALL GENERIC!)  ****/

int
authenticateActiveSchemeCount(void)
{
    int rv = 0;

    for (Auth::ConfigVector::iterator i = Auth::TheConfig.begin(); i != Auth::TheConfig.end(); ++i)
        if ((*i)->configured())
            ++rv;

    debugs(29, 9, HERE << rv << " active.");

    return rv;
}

int
authenticateSchemeCount(void)
{
    int rv = Auth::Scheme::GetSchemes().size();

    debugs(29, 9, HERE << rv << " active.");

    return rv;
}

static void
authenticateRegisterWithCacheManager(Auth::ConfigVector * config)
{
    for (Auth::ConfigVector::iterator i = config->begin(); i != config->end(); ++i) {
        Auth::Config *scheme = *i;
        scheme->registerWithCacheManager();
    }
}

void
authenticateInit(Auth::ConfigVector * config)
{
    /* Do this first to clear memory and remove dead state on a reconfigure */
    if (proxy_auth_username_cache)
        Auth::User::CachedACLsReset();

    /* If we do not have any auth config state to create stop now. */
    if (!config)
        return;

    for (Auth::ConfigVector::iterator i = config->begin(); i != config->end(); ++i) {
        Auth::Config *schemeCfg = *i;

        if (schemeCfg->configured())
            schemeCfg->init(schemeCfg);
    }

    if (!proxy_auth_username_cache)
        Auth::User::cacheInit();

    authenticateRegisterWithCacheManager(config);
}

void
authenticateRotate(void)
{
    for (Auth::ConfigVector::iterator i = Auth::TheConfig.begin(); i != Auth::TheConfig.end(); ++i)
        if ((*i)->configured())
            (*i)->rotateHelpers();
}

void
authenticateReset(void)
{
    debugs(29, 2, HERE << "Reset authentication State.");

    /* free all username cache entries */
    hash_first(proxy_auth_username_cache);
    AuthUserHashPointer *usernamehash;
    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        debugs(29, 5, HERE << "Clearing entry for user: " << usernamehash->user()->username());
        hash_remove_link(proxy_auth_username_cache, (hash_link *)usernamehash);
        delete usernamehash;
    }

    /* schedule shutdown of the helpers */
    authenticateRotate();

    /* free current global config details too. */
    Auth::TheConfig.clean();
}

AuthUserHashPointer::AuthUserHashPointer(Auth::User::Pointer anAuth_user):
        auth_user(anAuth_user)
{
    key = (void *)anAuth_user->username();
    next = NULL;
    hash_join(proxy_auth_username_cache, (hash_link *) this);
}

Auth::User::Pointer
AuthUserHashPointer::user() const
{
    return auth_user;
}
