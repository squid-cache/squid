/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_AUTH_NTLM_SCHEME_H
#define SQUID_AUTH_NTLM_SCHEME_H

#include "auth/Scheme.h"

namespace Auth
{
namespace Ntlm
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
    /**
     * Main instance of this authentication Scheme.
     * NULL when the scheme is not being used.
     */
    static Auth::Scheme::Pointer _instance;
};

} // namespace Ntlm
} // namespace Auth

#endif /* SQUID_AUTH_NTLM_SCHEME_H */

