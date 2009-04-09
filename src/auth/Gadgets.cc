
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

    for (authConfig::iterator i = Config.authConfiguration.begin(); i != Config.authConfiguration.end(); ++i)
        if ((*i)->configured())
            ++rv;

    debugs(29, 9, "authenticateActiveSchemeCount: " << rv << " active.");

    return rv;
}

int
authenticateSchemeCount(void)
{
    int rv = AuthScheme::Schemes().size();

    debugs(29, 9, "authenticateSchemeCount: " << rv << " active.");

    return rv;
}

static void
authenticateRegisterWithCacheManager(authConfig * config)
{
    for (authConfig::iterator i = config->begin(); i != config->end(); ++i) {
        AuthConfig *scheme = *i;
        scheme->registerWithCacheManager();
    }
}

void
authenticateInit(authConfig * config)
{
    for (authConfig::iterator i = config->begin(); i != config->end(); ++i) {
        AuthConfig *scheme = *i;

        if (scheme->configured())
            scheme->init(scheme);
    }

    if (!proxy_auth_username_cache)
        AuthUser::cacheInit();
    else
        AuthUser::CachedACLsReset();

    authenticateRegisterWithCacheManager(&Config.authConfiguration);
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
        for (AuthScheme::const_iterator i = AuthScheme::Schemes().begin(); i != AuthScheme::Schemes().end(); ++i)
            (*i)->done();
    }
}

/**
 \retval 0 not in use
 \retval ? in use
 */
int
authenticateAuthUserInuse(AuthUser * auth_user)
{
    assert(auth_user != NULL);
    return auth_user->references;
}

void
authenticateAuthUserMerge(AuthUser * from, AuthUser * to)
{
    to->absorb (from);
}

/**
 * Cleans all config-dependent data from the auth_user cache.
 \note It DOES NOT Flush the user cache.
 */
void
authenticateUserCacheRestart(void)
{
    AuthUserHashPointer *usernamehash;
    AuthUser *auth_user;
    debugs(29, 3, HERE << "Clearing config dependent cache data.");
    hash_first(proxy_auth_username_cache);

    while ((usernamehash = ((AuthUserHashPointer *) hash_next(proxy_auth_username_cache)))) {
        auth_user = usernamehash->user();
        debugs(29, 5, "authenticateUserCacheRestat: Clearing cache ACL results for user: " << auth_user->username());
    }
}


void
AuthUserHashPointer::removeFromCache(void *usernamehash_p)
{
    AuthUserHashPointer *usernamehash = static_cast<AuthUserHashPointer *>(usernamehash_p);
    AuthUser *auth_user = usernamehash->auth_user;

    if ((authenticateAuthUserInuse(auth_user) - 1))
        debugs(29, 1, "AuthUserHashPointer::removeFromCache: entry in use - not freeing");

    auth_user->unlock();

    /** \todo change behaviour - we remove from the auth user list here, and then unlock, and the
     * delete ourselves.
     */
}

AuthUserHashPointer::AuthUserHashPointer(AuthUser * anAuth_user):
        auth_user(anAuth_user)
{
    key = (void *)anAuth_user->username();
    next = NULL;
    hash_join(proxy_auth_username_cache, (hash_link *) this);

    /** lock for presence in the cache */
    auth_user->lock();
}

AuthUser *
AuthUserHashPointer::user() const
{
    return auth_user;
}
