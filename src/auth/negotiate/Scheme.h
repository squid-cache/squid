/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_NEGOTIATE_SCHEME_H
#define SQUID_AUTH_NEGOTIATE_SCHEME_H

#if HAVE_AUTH_MODULE_NEGOTIATE

#include "auth/Scheme.h"

namespace Auth
{
namespace Negotiate
{

/// \ingroup AuthSchemeAPI
/// \ingroup AuthAPI
class Scheme : public Auth::Scheme
{

public:
    static Auth::Scheme::Pointer GetInstance();
    Scheme() {};
    virtual ~Scheme() {};

    /* per scheme */
    virtual char const *type() const;
    virtual void shutdownCleanup();
    virtual Auth::Config *createConfig();

    /* Not implemented */
    Scheme (Scheme const &);
    Scheme &operator=(Scheme const &);

private:
    static Auth::Scheme::Pointer _instance;
};

} // namespace Negotiate
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_NEGOTIATE */
#endif /* SQUID_AUTH_NEGOTIATE_SCHEME_H */

