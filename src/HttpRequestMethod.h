/*
 * $Id: HttpRequestMethod.h,v 1.8 2008/02/03 10:00:29 amosjeffries Exp $
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
#include "SquidString.h"

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
    METHOD_OTHER,
    METHOD_ENUM_END  // MUST be last, (yuck) this is used as an array-initialization index constant!
};

/* forward decls */
typedef struct _SquidConfig SquidConfig;


/**
 * This class represents an HTTP Request METHOD
 * - i.e. PUT, POST, GET etc.
 * It has a runtime extension facility to allow it to
 * efficiently support new methods
 \ingroup POD
 */
class HttpRequestMethod
{

public:
    static void AddExtension(const char *methodString);
    static void Configure(SquidConfig &Config);

    HttpRequestMethod() : theMethod(METHOD_NONE), theImage() {}

    HttpRequestMethod(_method_t const aMethod) : theMethod(aMethod), theImage() {}

    /**
     \param begin    string to convert to request method.
     \param end      end of the method string (relative to begin). Use NULL if this is unknown.
     *
     \note DO NOT give end a default (ie NULL). That will cause silent char* conversion clashes.
     */
    HttpRequestMethod(char const * begin, char const * end);

    HttpRequestMethod & operator = (const HttpRequestMethod& aMethod)
    {
        theMethod = aMethod.theMethod;
        theImage = aMethod.theImage;
        return *this;
    }

    HttpRequestMethod & operator = (_method_t const aMethod)
    {
        theMethod = aMethod;
        theImage.clean();
        return *this;
    }

    bool operator == (_method_t const & aMethod) const { return theMethod == aMethod; }
    bool operator == (HttpRequestMethod const & aMethod) const
    {
        return ( (theMethod == aMethod.theMethod) || (theImage == aMethod.theImage) );
    }

    bool operator != (_method_t const & aMethod) const { return theMethod != aMethod; }
    bool operator != (HttpRequestMethod const & aMethod) const
    {
        return ( (theMethod != aMethod.theMethod) || (theImage != aMethod.theImage) ); 
    }

    /** Iterate through the registered HTTP methods. */
    HttpRequestMethod& operator++()
    {
        if(METHOD_OTHER != theMethod) {
            int tmp = (int)theMethod;
            _method_t tmp_m = (_method_t)(++tmp);

            if (METHOD_ENUM_END >= tmp_m)
                theMethod = tmp_m;
    	}
    	return *this;
    }

    /** Get an ID representation of the method.
     \retval METHOD_NONE	the methopd is currently unset or unknown.
     \retval METHOD_UNKNOWN	the method has been accepted but is not one of the registerd HTTP methods.
     \retval *			the method is on of the registered HTTP methods.
     */
    _method_t const id() const { return theMethod; }

    /** Get a char string representation of the method. */
    char const* image() const;

    bool isCacheble() const;

private:
    static const char *RequestMethodStr[];

    _method_t theMethod; ///< Method type
    String theImage;     ///< Used for store METHOD_OTHER only
};

inline std::ostream &
operator << (std::ostream &os, HttpRequestMethod const &method)
{
    os << method.image();
    return os;
}

inline const char*
RequestMethodStr(const _method_t m) 
{
   return HttpRequestMethod(m).image();
}

inline const char*
RequestMethodStr(const HttpRequestMethod& m) 
{
   return m.image();
}

#endif /* SQUID_HTTPREQUESTMETHOD_H */
