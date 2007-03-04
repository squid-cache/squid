
/*
 * $Id: HttpRequestMethod.h,v 1.4 2007/03/03 18:25:05 hno Exp $
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

#ifndef SQUID_HTTPREQUESTMETHOD_H
#define SQUID_HTTPREQUESTMETHOD_H

#include <iosfwd>

enum _method_t {
    METHOD_NONE,		/* 000 */
    METHOD_GET,			/* 001 */
    METHOD_POST,		/* 010 */
    METHOD_PUT,			/* 011 */
    METHOD_HEAD,		/* 100 */
    METHOD_CONNECT,		/* 101 */
    METHOD_TRACE,		/* 110 */
    METHOD_PURGE,		/* 111 */
    METHOD_OPTIONS,
    METHOD_DELETE,		/* RFC2616 section 9.7 */
    METHOD_PROPFIND,
    METHOD_PROPPATCH,
    METHOD_MKCOL,
    METHOD_COPY,
    METHOD_MOVE,
    METHOD_LOCK,
    METHOD_UNLOCK,
    METHOD_BMOVE,
    METHOD_BDELETE,
    METHOD_BPROPFIND,
    METHOD_BPROPPATCH,
    METHOD_BCOPY,
    METHOD_SEARCH,
    METHOD_SUBSCRIBE,
    METHOD_UNSUBSCRIBE,
    METHOD_POLL,
    METHOD_REPORT,
    METHOD_MKACTIVITY,
    METHOD_CHECKOUT,
    METHOD_MERGE,
    METHOD_EXT00,
    METHOD_EXT01,
    METHOD_EXT02,
    METHOD_EXT03,
    METHOD_EXT04,
    METHOD_EXT05,
    METHOD_EXT06,
    METHOD_EXT07,
    METHOD_EXT08,
    METHOD_EXT09,
    METHOD_EXT10,
    METHOD_EXT11,
    METHOD_EXT12,
    METHOD_EXT13,
    METHOD_EXT14,
    METHOD_EXT15,
    METHOD_EXT16,
    METHOD_EXT17,
    METHOD_EXT18,
    METHOD_EXT19,
    METHOD_ENUM_END
};

typedef enum _method_t method_t;

extern const char *RequestMethodStr[];

/* forward decls */

typedef struct _SquidConfig SquidConfig;


/* This class represents an HTTP Request METHOD - i.e.
 * PUT, POST, GET etc. It has a runtime extensionf acility to allow it to
 * efficiently support new methods
 */

class HttpRequestMethod
{

public:
    static void AddExtension(const char *methodString);
    static void Configure(SquidConfig &Config);

    HttpRequestMethod() : theMethod(METHOD_NONE) {}

    HttpRequestMethod(method_t const aMethod) : theMethod(aMethod) {}

    HttpRequestMethod(char const * begin, char const * end=0);

    operator method_t() const {return theMethod; }

    HttpRequestMethod & operator = (method_t const aMethod)
    {
        theMethod = aMethod;
        return *this;
    }

    bool operator != (method_t const & aMethod) { return theMethod != aMethod;}

    /* Get a char string representation of the method. */
    char const *const_str() const { return RequestMethodStr[theMethod]; }

private:
    method_t theMethod;

};

inline bool operator != (HttpRequestMethod const &left, method_t const &right) { return right != left; }

inline std::ostream &
operator << (std::ostream &os, HttpRequestMethod const &method)
{
    os << method.const_str();
    return os;
}

#endif /* SQUID_HTTPREQUESTMETHOD_H */
