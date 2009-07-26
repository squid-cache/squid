
/*
 * $Id$
 *
 * DEBUG: section 25    MiME Header Parsing
 * AUTHOR: Harvest Derived
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

#include "squid.h"

#define GET_HDR_SZ 1024

/* returns a pointer to a field-value of the first matching field-name */
char *
mime_get_header(const char *mime, const char *name)
{
    return mime_get_header_field(mime, name, NULL);
}

/*
 * returns a pointer to a field-value of the first matching field-name where
 * field-value matches prefix if any
 */
char *
mime_get_header_field(const char *mime, const char *name, const char *prefix)
{
    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *p = NULL;
    char *q = NULL;
    char got = 0;
    const int namelen = name ? strlen(name) : 0;
    const int preflen = prefix ? strlen(prefix) : 0;
    int l;

    if (NULL == mime)
        return NULL;

    assert(NULL != name);

    debugs(25, 5, "mime_get_header: looking for '" << name << "'");

    for (p = mime; *p; p += strcspn(p, "\n\r")) {
        if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
            return NULL;

        while (xisspace(*p))
            p++;

        if (strncasecmp(p, name, namelen))
            continue;

        if (!xisspace(p[namelen]) && p[namelen] != ':')
            continue;

        l = strcspn(p, "\n\r") + 1;

        if (l > GET_HDR_SZ)
            l = GET_HDR_SZ;

        xstrncpy(header, p, l);

        debugs(25, 5, "mime_get_header: checking '" << header << "'");

        q = header;

        q += namelen;

        if (*q == ':')
            q++, got = 1;

        while (xisspace(*q))
            q++, got = 1;

        if (got && prefix) {
            /* we could process list entries here if we had strcasestr(). */
            /* make sure we did not match a part of another field-value */
            got = !strncasecmp(q, prefix, preflen) && !xisalpha(q[preflen]);
        }

        if (got) {
            debugs(25, 5, "mime_get_header: returning '" << q << "'");
            return q;
        }
    }

    return NULL;
}

size_t
headersEnd(const char *mime, size_t l)
{
    size_t e = 0;
    int state = 1;

    PROF_start(headersEnd);

    while (e < l && state < 3) {
        switch (state) {

        case 0:

            if ('\n' == mime[e])
                state = 1;

            break;

        case 1:
            if ('\r' == mime[e])
                state = 2;
            else if ('\n' == mime[e])
                state = 3;
            else
                state = 0;

            break;

        case 2:
            if ('\n' == mime[e])
                state = 3;
            else
                state = 0;

            break;

        default:
            break;
        }

        e++;
    }
    PROF_stop(headersEnd);

    if (3 == state)
        return e;

    return 0;
}
