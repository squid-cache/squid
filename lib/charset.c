/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "charset.h"

/** Convert ISO-LATIN-1 to UTF-8 */
char *
latin1_to_utf8(char *out, size_t size, const char *in)
{
    unsigned char *p = (unsigned char *)out;
    for (; *in && size > 2; in++) {
        unsigned char ch = (unsigned char)*in;
        if (ch < 0x80) {
            *p++ = ch;
            size--;
        } else {
            *p++ = (ch >> 6) | 0xc0;
            size--;
            *p++ = (ch & 0x3f) | 0x80;
            size--;
        }
    }
    *p = '\0';
    if (*in)
        return NULL;
    return out;
}

