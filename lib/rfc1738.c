/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "rfc1738.h"

#if HAVE_STRING_H
#include <string.h>
#endif

/*
 *  RFC 1738 defines that these characters should be escaped, as well
 *  any non-US-ASCII character or anything between 0x00 - 0x1F.
 */
static char rfc1738_unsafe_chars[] = {
    (char) 0x3C,        /* < */
    (char) 0x3E,        /* > */
    (char) 0x22,        /* " */
    (char) 0x23,        /* # */
#if 0               /* done in code */
    (char) 0x20,        /* space */
    (char) 0x25,        /* % */
#endif
    (char) 0x7B,        /* { */
    (char) 0x7D,        /* } */
    (char) 0x7C,        /* | */
    (char) 0x5C,        /* \ */
    (char) 0x5E,        /* ^ */
    (char) 0x7E,        /* ~ */
    (char) 0x5B,        /* [ */
    (char) 0x5D,        /* ] */
    (char) 0x60,        /* ` */
    (char) 0x27         /* ' */
};

static char rfc1738_reserved_chars[] = {
    (char) 0x3b,        /* ; */
    (char) 0x2f,        /* / */
    (char) 0x3f,        /* ? */
    (char) 0x3a,        /* : */
    (char) 0x40,        /* @ */
    (char) 0x3d,        /* = */
    (char) 0x26         /* & */
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
    const char *src;
    char *dst;
    unsigned int i, do_escape;

    if (buf == NULL || strlen(url) * 3 > bufsize) {
        xfree(buf);
        bufsize = strlen(url) * 3 + 1;
        buf = (char*)xcalloc(bufsize, 1);
    }
    for (src = url, dst = buf; *src != '\0' && dst < (buf + bufsize - 1); src++, dst++) {

        /* a-z, A-Z and 0-9 are SAFE. */
        if ((*src >= 'a' && *src <= 'z') || (*src >= 'A' && *src <= 'Z') || (*src >= '0' && *src <= '9')) {
            *dst = *src;
            continue;
        }

        do_escape = 0;

        /* RFC 1738 defines these chars as unsafe */
        if ((flags & RFC1738_ESCAPE_UNSAFE)) {
            for (i = 0; i < sizeof(rfc1738_unsafe_chars); i++) {
                if (*src == rfc1738_unsafe_chars[i]) {
                    do_escape = 1;
                    break;
                }
            }
            /* Handle % separately */
            if (!(flags & RFC1738_ESCAPE_NOPERCENT) && *src == '%')
                do_escape = 1;
            /* Handle space separately */
            else if (!(flags & RFC1738_ESCAPE_NOSPACE) && *src <= ' ')
                do_escape = 1;
        }
        /* RFC 1738 defines these chars as reserved */
        if ((flags & RFC1738_ESCAPE_RESERVED) && do_escape == 0) {
            for (i = 0; i < sizeof(rfc1738_reserved_chars); i++) {
                if (*src == rfc1738_reserved_chars[i]) {
                    do_escape = 1;
                    break;
                }
            }
        }
        if ((flags & RFC1738_ESCAPE_CTRLS) && do_escape == 0) {
            /* RFC 1738 says any control chars (0x00-0x1F) are encoded */
            if ((unsigned char) *src <= (unsigned char) 0x1F)
                do_escape = 1;
            /* RFC 1738 says 0x7f is encoded */
            else if (*src == (char) 0x7F)
                do_escape = 1;
            /* RFC 1738 says any non-US-ASCII are encoded */
            else if (((unsigned char) *src >= (unsigned char) 0x80))
                do_escape = 1;
        }
        /* Do the triplet encoding, or just copy the char */
        if (do_escape == 1) {
            (void) snprintf(dst, (bufsize-(dst-buf)), "%%%02X", (unsigned char) *src);
            dst += sizeof(char) * 2;
        } else {
            *dst = *src;
        }
    }
    *dst = '\0';
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
    int i, j;           /* i is write, j is read */
    for (i = j = 0; s[j]; i++, j++) {
        s[i] = s[j];
        if (s[j] != '%') {
            /* normal case, nothing more to do */
        } else if (s[j + 1] == '%') {   /* %% case */
            j++;        /* Skip % */
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

