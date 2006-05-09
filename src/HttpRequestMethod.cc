
/*
 * $Id: HttpRequestMethod.cc,v 1.1 2006/05/08 23:38:33 robertc Exp $
 *
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

const char *RequestMethodStr[] =
    {
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
        "%EXT00",
        "%EXT01",
        "%EXT02",
        "%EXT03",
        "%EXT04",
        "%EXT05",
        "%EXT06",
        "%EXT07",
        "%EXT08",
        "%EXT09",
        "%EXT10",
        "%EXT11",
        "%EXT12",
        "%EXT13",
        "%EXT14",
        "%EXT15",
        "%EXT16",
        "%EXT17",
        "%EXT18",
        "%EXT19",
        "ERROR"
    };

static
method_t &operator++ (method_t &aMethod)
{
    int tmp = (int)aMethod;
    aMethod = (method_t)(++tmp);
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

    for (++theMethod; theMethod < METHOD_ENUM_END; ++theMethod) {
        if (0 == strncasecmp(begin, RequestMethodStr[theMethod], end-begin))
            return;
    }

    /* reset to none */
    theMethod = METHOD_NONE;
}

void
HttpRequestMethod::AddExtension(const char *mstr)
{
    method_t method = METHOD_NONE;

    for (++method; method < METHOD_ENUM_END; ++method) {
        if (0 == strcmp(mstr, RequestMethodStr[method])) {
            debug(23, 2) ("Extension method '%s' already exists\n", mstr);
            return;
        }

        if (0 != strncmp("%EXT", RequestMethodStr[method], 4))
            continue;

        /* Don't free statically allocated "%EXTnn" string */
        RequestMethodStr[method] = xstrdup(mstr);

        debug(23, 1) ("Extension method '%s' added, enum=%d\n", mstr, (int) method);

        return;
    }

    debug(23, 1) ("WARNING: Could not add new extension method '%s' due to lack of array space\n", mstr);
}

void
HttpRequestMethod::Configure(SquidConfig &Config)
{
    wordlist *w = Config.ext_methods;

    while (w) {
        char *s;

        for (s = w->key; *s; s++)
            *s = xtoupper(*s);

        AddExtension(w->key);

        w = w->next;
    }
}
