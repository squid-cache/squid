/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_SCHEMESCONFIG_H
#define SQUID_SRC_AUTH_SCHEMESCONFIG_H

#if USE_AUTH

#include "auth/SchemeConfig.h"

namespace Auth
{

/**
 * Stores authentication schemes list, configured by auth_schemes
 * directive.
 */
class SchemesConfig
{
public:
    SchemesConfig(const char *s, const bool q) : schemes(s), quoted(q), rawSchemes(schemes.c_str()) {}
    /// Expands special "ALL" scheme name (if provided), removes
    /// duplicates and fills authConfigs vector.
    void expand();

public:
    /// corresponding vector of Auth::Config objects
    Auth::ConfigVector authConfigs;

private:
    /// raw auth schemes list (may have duplicates)
    SBuf schemes;
    const bool quoted;

public:
    /// optimization for storing schemes.c_str()
    const char *rawSchemes;
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_SCHEMESCONFIG_H */

