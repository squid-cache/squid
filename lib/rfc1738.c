/*
 * $Id$
 *
 * DEBUG:
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

#include "config.h"
#include "rfc1738.h"
#include "util.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

/*
 *  RFC 1738 defines that these characters should be escaped, as well
 *  any non-US-ASCII character or anything between 0x00 - 0x1F.
 */
static char rfc1738_unsafe_chars[] = {
    (char) 0x3C,		/* < */
    (char) 0x3E,		/* > */
    (char) 0x22,		/* " */
    (char) 0x23,		/* # */
#if 0				/* done in code */
    (char) 0x25,		/* % */
#endif
    (char) 0x7B,		/* { */
    (char) 0x7D,		/* } */
    (char) 0x7C,		/* | */
    (char) 0x5C,		/* \ */
    (char) 0x5E,		/* ^ */
    (char) 0x7E,		/* ~ */
    (char) 0x5B,		/* [ */
    (char) 0x5D,		/* ] */
    (char) 0x60,		/* ` */
    (char) 0x27,		/* ' */
    (char) 0x20			/* space */
};

static char rfc1738_reserved_chars[] = {
    (char) 0x3b,		/* ; */
    (char) 0x2f,		/* / */
    (char) 0x3f,		/* ? */
    (char) 0x3a,		/* : */
    (char) 0x40,		/* @ */
    (char) 0x3d,		/* = */
    (char) 0x26			/* & */
};

/*
 *  rfc1738_escape - Returns a static buffer contains the RFC 1738
 *  compliant, escaped version of the given url.
 */
char *
rfc1738_do_escape(const char *url, int flags)
{
    static char *buf;
    static size_t bufsize = 0;
    const char *p;
    char *q;
    unsigned int i, do_escape;

    if (buf == NULL || strlen(url) * 3 > bufsize) {
        xfree(buf);
        bufsize = strlen(url) * 3 + 1;
        buf = (char*)xcalloc(bufsize, 1);
    }
    for (p = url, q = buf; *p != '\0' && q < (buf + bufsize - 1); p++, q++) {
        do_escape = 0;

        /* RFC 1738 defines these chars as unsafe */
        for (i = 0; i < sizeof(rfc1738_unsafe_chars); i++) {
            if (*p == rfc1738_unsafe_chars[i]) {
                do_escape = 1;
                break;
            }
        }
        /* Handle % separately */
        if (flags != RFC1738_ESCAPE_UNESCAPED && *p == '%')
            do_escape = 1;
        /* RFC 1738 defines these chars as reserved */
        for (i = 0; i < sizeof(rfc1738_reserved_chars) && flags == RFC1738_ESCAPE_RESERVED; i++) {
            if (*p == rfc1738_reserved_chars[i]) {
                do_escape = 1;
                break;
            }
        }
        /* RFC 1738 says any control chars (0x00-0x1F) are encoded */
        if ((unsigned char) *p <= (unsigned char) 0x1F) {
            do_escape = 1;
        }
        /* RFC 1738 says 0x7f is encoded */
        if (*p == (char) 0x7F) {
            do_escape = 1;
        }
        /* RFC 1738 says any non-US-ASCII are encoded */
        if (((unsigned char) *p >= (unsigned char) 0x80)) {
            do_escape = 1;
        }
        /* Do the triplet encoding, or just copy the char */
        /* note: we do not need snprintf here as q is appropriately
         * allocated - KA */

        if (do_escape == 1) {
            (void) snprintf(q, (bufsize-(p-buf)), "%%%02X", (unsigned char) *p);
            q += sizeof(char) * 2;
        } else {
            *q = *p;
        }
    }
    *q = '\0';
    return (buf);
}

/*
 * Converts a ascii hex code into a binary character.
 */
static int
fromhex(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

/*
 *  rfc1738_unescape() - Converts escaped characters (%xy numbers) in
 *  given the string.  %% is a %. %ab is the 8-bit hexadecimal number "ab"
 */
void
rfc1738_unescape(char *s)
{
    int i, j;			/* i is write, j is read */
    for (i = j = 0; s[j]; i++, j++) {
        s[i] = s[j];
        if (s[j] != '%') {
            /* normal case, nothing more to do */
        } else if (s[j + 1] == '%') {	/* %% case */
            j++;		/* Skip % */
        } else {
            /* decode */
            int v1, v2, x;
            v1 = fromhex(s[j + 1]);
            if (v1 < 0)
                continue;  /* non-hex or \0 */
            v2 = fromhex(s[j + 2]);
            if (v2 < 0)
                continue;  /* non-hex or \0 */
            x = v1 << 4 | v2;
            if (x > 0 && x <= 255) {
                s[i] = x;
                j += 2;
            }
        }
    }
    s[i] = '\0';
}
