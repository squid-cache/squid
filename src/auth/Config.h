/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_CONFIG_H
#define SQUID_SRC_AUTH_CONFIG_H

#if USE_AUTH

#include "acl/forward.h"
#include "auth/SchemeConfig.h"
#include "auth/SchemesConfig.h"

namespace Auth
{

class Config
{
public:
    Config() = default;
    Config(Config &&) = delete; // no support for copying of any kind
    ~Config() = default;

    /// set of auth_params directives
    Auth::ConfigVector schemes;

    /// set of auth_schemes directives
    std::vector<Auth::SchemesConfig> schemeLists;

    /// the ACL list for auth_schemes directives
    acl_access *schemeAccess = nullptr;

    /// the authenticate_cache_garbage_interval
    time_t garbageCollectInterval = 0;

    // TODO replace this directive with per-Scheme 'credentialsttl'
    //      and make Scheme::expirestime the real time-when-expires.
    /// the authenticate_ttl
    time_t credentialsTtl = 0;

    /// the authenticate_ip_ttl
    time_t ipTtl = 0;
};

extern Auth::Config TheConfig;

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_CONFIG_H */

