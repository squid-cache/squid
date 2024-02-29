/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_SCHEME_H
#define SQUID_SRC_AUTH_SCHEME_H

#if USE_AUTH

#include "auth/forward.h"
#include "base/RefCount.h"

namespace Auth
{

/**
 * I represent an authentication scheme. For now my children
 * store the scheme metadata.
 *
 * Should we need multiple configs of a single scheme,
 * a new class should be made, and the config specific calls on Auth::Scheme moved to it.
 */
class Scheme : public RefCountable
{
public:
    typedef RefCount<Scheme> Pointer;
    typedef std::vector<Scheme::Pointer>::iterator iterator;
    typedef std::vector<Scheme::Pointer>::const_iterator const_iterator;

public:
    Scheme() : initialised (false) {};
    ~Scheme() override {};

    static void AddScheme(Scheme::Pointer);

    /**
     * Final termination of all authentication components.
     * To be used only on shutdown. All global pointers are released.
     * After this all schemes will appear completely unsupported
     * until a call to InitAuthModules().
     * Release the Auth::TheConfig handles instead to disable authentication
     * without terminiating all support.
     */
    static void FreeAll();

    /**
     * Locate an authentication scheme component by Name.
     */
    static Scheme::Pointer Find(const char *);

    /* per scheme methods */
    virtual char const *type() const = 0;
    virtual void shutdownCleanup() = 0;
    virtual Auth::SchemeConfig *createConfig() = 0;

    // Not implemented
    Scheme(Scheme const &);
    Scheme &operator=(Scheme const&);

    static std::vector<Scheme::Pointer> &GetSchemes();

protected:
    bool initialised;

private:
    static std::vector<Scheme::Pointer> *_Schemes;
};

} // namespace Auth

#endif /* USE_AUTH */
#endif /* SQUID_SRC_AUTH_SCHEME_H */

