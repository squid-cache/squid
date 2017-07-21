/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_BEARER_SCHEME_H
#define SQUID_AUTH_BEARER_SCHEME_H

#if HAVE_AUTH_MODULE_BEARER

#include "auth/Scheme.h"

namespace Auth
{
namespace Bearer
{

/// scheme instance for OAuth 2.0 Bearer
class Scheme : public Auth::Scheme
{
public:
    Scheme() = default;
    virtual ~Scheme() {}

    static Auth::Scheme::Pointer GetInstance();

    /* Auth::Scheme API */
    char const *type() const override;
    void shutdownCleanup() override;
    Auth::SchemeConfig *createConfig() override;

private:
    static Auth::Scheme::Pointer _instance;
};

} // namespace Bearer
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BEARER */
#endif /* SQUID_AUTH_BEARER_SCHEME_H */
