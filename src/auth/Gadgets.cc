/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/FilledChecklist.h"
#include "auth/AclProxyAuth.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/Scheme.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "client_side.h"
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
    Auth::TheConfig.clear();
}

AuthUserHashPointer::AuthUserHashPointer(Auth::User::Pointer anAuth_user):
    auth_user(anAuth_user)
{
    key = (void *)anAuth_user->userKey();
    next = NULL;
    hash_join(proxy_auth_username_cache, (hash_link *) this);
}

Auth::User::Pointer
AuthUserHashPointer::user() const
{
    return auth_user;
}

