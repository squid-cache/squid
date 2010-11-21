/*
 * $Id$
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_AUTHSCHEME_H
#define SQUID_AUTHSCHEME_H

#include "Array.h"
#include "RefCount.h"

class AuthConfig;

/**
 \defgroup AuthSchemeAPI	Authentication Scheme API
 \ingroup AuthAPI
 */

/**
 * \ingroup AuthAPI
 * \ingroup AuthSchemeAPI
 * \par
 * I represent an authentication scheme. For now my children
 * store the scheme metadata.
 * \par
 * Should we need multiple configs of a single scheme,
 * a new class AuthConfiguration should be made, and the
 * config specific calls on AuthScheme moved to it.
 */
class AuthScheme : public RefCountable
{
public:
    typedef RefCount<AuthScheme> Pointer;
    typedef Vector<AuthScheme::Pointer>::iterator iterator;
    typedef Vector<AuthScheme::Pointer>::const_iterator const_iterator;

public:
    AuthScheme() : initialised (false) {};
    virtual ~AuthScheme() {};

    static void AddScheme(AuthScheme::Pointer);

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
    static AuthScheme::Pointer Find(const char *);

    /* per scheme methods */
    virtual char const *type () const = 0;
    virtual void done() = 0;
    virtual AuthConfig *createConfig() = 0;

    // Not implemented
    AuthScheme(AuthScheme const &);
    AuthScheme &operator=(AuthScheme const&);

    static Vector<AuthScheme::Pointer> &GetSchemes();

protected:
    bool initialised;

private:
    static Vector<AuthScheme::Pointer> *_Schemes;
};

#endif /* SQUID_AUTHSCHEME_H */
