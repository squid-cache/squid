/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_BASIC_SCHEME_H
#define SQUID_AUTH_BASIC_SCHEME_H

#if HAVE_AUTH_MODULE_BASIC

#include "auth/Scheme.h"

namespace Auth
{
namespace Basic
{

/// \ingroup AuthAPI
/// \ingroup AuthSchemeAPI
class Scheme : public Auth::Scheme
{

public:
    static Auth::Scheme::Pointer GetInstance();
    Scheme() {};
    virtual ~Scheme() {}

    /* per scheme */
    virtual char const *type() const;
    virtual void shutdownCleanup();
    virtual Auth::Config *createConfig();
    /* Not implemented */
    Scheme(Scheme const &);
    Scheme &operator=(Scheme const &);

private:
    static Auth::Scheme::Pointer _instance;
};

} // namespace Basic
} // namespace Auth

#endif /* HAVE_AUTH_MODULE_BASIC */
#endif /* SQUID_AUTH_BASIC_SCHEME_H */

