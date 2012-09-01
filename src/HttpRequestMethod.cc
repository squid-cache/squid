
/*
 * DEBUG: section 73    HTTP Request
 * AUTHOR: Duane Wessels
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "HttpRequestMethod.h"
#include "wordlist.h"

const char* HttpRequestMethod::RequestMethodStr[] = {
    "NONE",
    "GET",
    "POST",
    "PUT",
    "HEAD",
    "CONNECT",
    "TRACE",
    "PURGE",
    "OPTIONS",
    "DELETE",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "BMOVE",
    "BDELETE",
    "BPROPFIND",
    "BPROPPATCH",
    "BCOPY",
    "SEARCH",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "POLL",
    "REPORT",
    "MKACTIVITY",
    "CHECKOUT",
    "MERGE",
    "ERROR"
};

static
_method_t &operator++ (_method_t &aMethod)
{
    int tmp = (int)aMethod;
    aMethod = (_method_t)(++tmp);
    return aMethod;
}

/*
 * Construct a HttpRequestMethod from a NULL terminated string such as "GET"
 * or from a range of chars, * such as "GET" from "GETFOOBARBAZ"
 * (pass in pointer to G and pointer to F.)
 */
HttpRequestMethod::HttpRequestMethod(char const *begin, char const *end) : theMethod (METHOD_NONE)
{
    if (begin == NULL)
        return;

    /*
     * This check for '%' makes sure that we don't
     * match one of the extension method placeholders,
     * which have the form %EXT[0-9][0-9]
     */

    if (*begin == '%')
        return;

    /*
     * if e is NULL, b must be NULL terminated and we
     * make e point to the first whitespace character
     * after b.
     */
    if (NULL == end)
        end = begin + strcspn(begin, w_space);

    if (end == begin) {
        theMethod = METHOD_NONE;
        return;
    }

    for (++theMethod; theMethod < METHOD_ENUM_END; ++theMethod) {
        if (0 == strncasecmp(begin, RequestMethodStr[theMethod], end-begin)) {
            return;
        }
    }

    // if method not found and method string is not null then it is other method
    theMethod = METHOD_OTHER;
    theImage.limitInit(begin,end-begin);
}

/** \todo AYJ: this _should_ be obsolete. Since all such methods fit nicely into METHOD_OTHER now. */
void
HttpRequestMethod::AddExtension(const char *mstr)
{
#if 0 /* obsolete now that we have METHOD_OTHER always enabled */
    _method_t method = METHOD_NONE;

    for (++method; method < METHOD_ENUM_END; ++method) {
        if (0 == strcmp(mstr, RequestMethodStr[method])) {
            debugs(23, 2, "Extension method '" << mstr << "' already exists");
            return;
        }

        if (0 != strncmp("%EXT", RequestMethodStr[method], 4))
            continue;

        /* Don't free statically allocated "%EXTnn" string */
        RequestMethodStr[method] = xstrdup(mstr);

        debugs(23, DBG_IMPORTANT, "Extension method '" << mstr << "' added, enum=" << method);

        return;
    }

    debugs(23, DBG_IMPORTANT, "WARNING: Could not add new extension method '" << mstr << "' due to lack of array space");
#endif
}

void
HttpRequestMethod::Configure(SquidConfig &cfg)
{
#if 0 /* extension methods obsolete now that we have METHOD_OTHER always enabled */
    wordlist *w = cfg.ext_methods;

    while (w) {
        char *s;

        for (s = w->key; *s; ++s)
            *s = xtoupper(*s);

        AddExtension(w->key);

        w = w->next;
    }
#endif
}

char const*
HttpRequestMethod::image() const
{
    if (METHOD_OTHER != theMethod) {
        return RequestMethodStr[theMethod];
    } else {
        if (theImage.size()>0) {
            return theImage.termedBuf();
        } else {
            return "METHOD_OTHER";
        }
    }
}

bool
HttpRequestMethod::isCacheble() const
{
    // TODO: optimize the lookup with a precomputed flags array
    // XXX: the list seems wrong; e.g., Is METHOD_DELETE really cachable?
    // see also http.cc::httpCachable()

    if (theMethod == METHOD_CONNECT)
        return false;

    if (theMethod == METHOD_TRACE)
        return false;

    if (theMethod == METHOD_PUT)
        return false;

    if (theMethod == METHOD_POST)
        return false;

    if (theMethod == METHOD_OTHER)
        return false;

    return true;
}

bool
HttpRequestMethod::purgesOthers() const
{
    // TODO: optimize the lookup with a precomputed flags array

    switch (theMethod) {
        /* common sense suggests purging is not required? */
    case METHOD_GET:     // XXX: but we do purge HEAD on successful GET
    case METHOD_HEAD:
    case METHOD_NONE:
    case METHOD_CONNECT:
    case METHOD_TRACE:
    case METHOD_OPTIONS:
    case METHOD_PROPFIND:
    case METHOD_BPROPFIND:
    case METHOD_COPY:
    case METHOD_BCOPY:
    case METHOD_LOCK:
    case METHOD_UNLOCK:
    case METHOD_SEARCH:
        return false;

        /* purging mandated by RFC 2616 */
    case METHOD_POST:
    case METHOD_PUT:
    case METHOD_DELETE:
        return true;

        /* purging suggested by common sense */
    case METHOD_PURGE:
        return true;

        /*
         * RFC 2616 sayeth, in section 13.10, final paragraph:
         * A cache that passes through requests for methods it does not
         * understand SHOULD invalidate any entities referred to by the
         * Request-URI.
         */
    case METHOD_OTHER:
    default:
        return true;
    }

    return true; // not reached, but just in case
}
