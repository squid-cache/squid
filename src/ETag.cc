
/*
 * $Id$
 *
 * DEBUG: none          ETag parsing support
 * AUTHOR: Alex Rousskov
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

/*
 * Note: ETag is not an http "field" like, for example HttpHdrRange. ETag is a
 * field-value that maybe used in many http fields.
 */

/// whether etag strings match
static bool
etagStringsMatch(const ETag &tag1, const ETag &tag2)
{
    return !strcmp(tag1.str, tag2.str);
}

/* parses a string as weak or strong entity-tag; returns true on success */
/* note: we do not duplicate "str"! */
int
etagParseInit(ETag * etag, const char *str)
{
    int len;
    assert(etag && str);
    etag->str = NULL;
    etag->weak = !strncmp(str, "W/", 2);

    if (etag->weak)
        str += 2;

    /* check format (quoted-string) */
    len = strlen(str);

    if (len >= 2 && str[0] == '"' && str[len - 1] == '"')
        etag->str = str;

    return etag->str != NULL;
}

bool
etagIsStrongEqual(const ETag &tag1, const ETag &tag2)
{
    return !tag1.weak && !tag2.weak && etagStringsMatch(tag1, tag2);
}

bool
etagIsWeakEqual(const ETag &tag1, const ETag &tag2)
{
    return etagStringsMatch(tag1, tag2);
}
