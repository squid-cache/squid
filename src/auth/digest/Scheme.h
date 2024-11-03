/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_DIGEST_SCHEME_H
#define SQUID_SRC_AUTH_DIGEST_SCHEME_H

#if HAVE_AUTH_MODULE_DIGEST

#include "auth/Scheme.h"

namespace Auth
{
namespace Digest
{

/// \ingroup AuthAPI
class Scheme : public Auth::Scheme
{

public:
    static Auth::Scheme::Pointer GetInstance();
    Scheme() {};
    ~Scheme() override {}

    /* per scheme */
    char const *type () const override;
    void shutdownCleanup() override;
    Auth::SchemeConfig *createConfig() override;

    /* Not implemented */
    Scheme(Scheme const &);
    Scheme &operator=(Scheme const &);

private:
    static Auth::Scheme::Pointer _instance;

};

} // namespace Digest
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_DIGEST */
#endif /* SQUID_SRC_AUTH_DIGEST_SCHEME_H */

