
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

#ifndef SQUID_URLSCHEME_H
#define SQUID_URLSCHEME_H

/* For the definition of NULL and protocol_t */
#include "squid.h"

#include <iosfwd>

extern const char *ProtocolStr[];

/* This class represents a URL Scheme such as HTTPS, HTTP, WAIS etc.
 * It does not represent the PROTOCOL that such schemes refer to.
 */

class URLScheme
{

public:
    URLScheme() : theScheme(PROTO_NONE) {}

    URLScheme(protocol_t const aScheme) : theScheme(aScheme) {}

    operator protocol_t() const { return theScheme; }

    bool operator != (protocol_t const & aProtocol) const { return theScheme != aProtocol;}

    /* Get a char string representation of the scheme. */
    char const *const_str() const { return ProtocolStr[theScheme]; }

private:
    /* This is a typecode for now - TODO make the varying methods virtual
     * Doing that without doubling the storage size will require having
     * something like a flyweight. perhaps the strategy pattern is appropiate:
     * one strategy per scheme, and an object that is nothing but a pointer
     * into the registry of schemes.
     */
    protocol_t theScheme;
};

inline std::ostream &
operator << (std::ostream &os, URLScheme const &scheme)
{
    os << scheme.const_str();
    return os;
}

#endif /* SQUID_URLSCHEME_H */
