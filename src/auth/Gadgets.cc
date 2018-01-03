/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
#include "auth/basic/User.h"
#include "auth/Config.h"
#include "auth/CredentialsCache.h"
#include "auth/digest/User.h"
#include "auth/Gadgets.h"
#include "auth/negotiate/User.h"
#include "auth/ntlm/User.h"
#include "auth/Scheme.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "client_side.h"
#include "globals.h"
#include "http/Stream.h"
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
    /* If we do not have any auth config state to create stop now. */
    if (!config)
        return;

    for (Auth::ConfigVector::iterator i = config->begin(); i != config->end(); ++i) {
        Auth::Config *schemeCfg = *i;

        if (schemeCfg->configured())
            schemeCfg->init(schemeCfg);
    }

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
    debugs(29, 2, "Reset authentication State.");

    // username cache is cleared via Runner registry

    /* schedule shutdown of the helpers */
    authenticateRotate();

    /* free current global config details too. */
    Auth::TheConfig.clear();
}

std::vector<Auth::User::Pointer>
authenticateCachedUsersList()
{
    auto aucp_compare = [=](const Auth::User::Pointer lhs, const Auth::User::Pointer rhs) {
        return lhs->userKey() < rhs->userKey();
    };
    std::vector<Auth::User::Pointer> v1, v2, rv, u1, u2;
#if HAVE_AUTH_MODULE_BASIC
    if (Auth::Config::Find("basic") != nullptr)
        u1 = Auth::Basic::User::Cache()->sortedUsersList();
#endif
#if HAVE_AUTH_MODULE_DIGEST
    if (Auth::Config::Find("digest") != nullptr)
        u2 = Auth::Digest::User::Cache()->sortedUsersList();
#endif
    if (u1.size() > 0 || u2.size() > 0) {
        v1.reserve(u1.size()+u2.size());
        std::merge(u1.begin(), u1.end(),u2.begin(), u2.end(),
                   std::back_inserter(v1), aucp_compare);
        u1.clear();
        u2.clear();
    }
#if HAVE_AUTH_MODULE_NEGOTIATE
    if (Auth::Config::Find("negotiate") != nullptr)
        u1 = Auth::Negotiate::User::Cache()->sortedUsersList();
#endif
#if HAVE_AUTH_MODULE_NTLM
    if (Auth::Config::Find("ntlm") != nullptr)
        u2 = Auth::Ntlm::User::Cache()->sortedUsersList();
#endif
    if (u1.size() > 0 || u2.size() > 0) {
        v2.reserve(u1.size()+u2.size());
        std::merge(u1.begin(), u1.end(),u2.begin(), u2.end(),
                   std::back_inserter(v2), aucp_compare);
    }
    rv.reserve(v1.size()+v2.size());
    std::merge(v1.begin(), v1.end(),v2.begin(), v2.end(),
               std::back_inserter(rv), aucp_compare);
    return rv;
}

