/*
 * $Id$
 *
 * DEBUG:
 * AUTHOR: Henrik Nordstrom <henrik@henriknordstrom.net>
 *
 * Copyright (C) 2008 Henrik Nordstrom
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
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
#include "util.h"

/* Convert ISO-LATIN-1 to UTF-8
 */
char *
latin1_to_utf8(char *out, size_t size, const char *in)
{
    unsigned char *p;
    for (p = (unsigned char *)out; *in && size > 2; in++) {
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
    *p++ = '\0';
    if (*in)
        return NULL;
    return out;
}


