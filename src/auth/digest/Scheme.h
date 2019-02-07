/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_DIGEST_SCHEME_H
#define SQUID_AUTH_DIGEST_SCHEME_H

#if HAVE_AUTH_MODULE_DIGEST

#include "auth/Scheme.h"

namespace Auth
{
namespace Digest
{

/// \ingroup AuthSchemeAPI
/// \ingroup AuthAPI
class Scheme : public Auth::Scheme
{

public:
    static Auth::Scheme::Pointer GetInstance();
    Scheme() {};
    virtual ~Scheme() {}

    /* per scheme */
    virtual char const *type () const;
    virtual void shutdownCleanup();
    virtual Auth::Config *createConfig();

    /* Not implemented */
    Scheme(Scheme const &);
    Scheme &operator=(Scheme const &);

private:
    static Auth::Scheme::Pointer _instance;

};

} // namespace Digest
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_DIGEST */
#endif /* SQUID_AUTH_DIGEST_SCHEME_H */

