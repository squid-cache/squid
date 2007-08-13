
/*
 * $Id: Parsing.cc,v 1.4 2007/08/13 17:20:51 hno Exp $
 *
 * DEBUG: section 3     Configuration File Parsing
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

#include "Parsing.h"

/*
 * These functions is the same as atoi/l/f, except that they check for errors
 */

double
xatof(const char *token)
{
    char *end;
    double ret = strtod(token, &end);

    if (ret == 0 && end == token)
        self_destruct();

    return ret;
}

int
xatoi(const char *token)
{
    return xatol(token);
}

long
xatol(const char *token)
{
    char *end;
    long ret = strtol(token, &end, 10);

    if (end == token || *end)
        self_destruct();

    return ret;
}

unsigned short
xatos(const char *token)
{
    long port = xatol(token);

    if (port & ~0xFFFF)
        self_destruct();

    return port;
}

int
GetInteger(void)
{
    char *token = strtok(NULL, w_space);
    int i;

    if (token == NULL)
        self_destruct();

    if (sscanf(token, "%d", &i) != 1)
        self_destruct();

    return i;
}

u_short
GetShort(void)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    return xatos(token);
}

bool
StringToInt(const char *s, int &result, const char **p, int base)
{
    if (s) {
        char *ptr = 0;
        const int h = (int) strtol(s, &ptr, base);

        if (ptr != s && ptr) {
            result = h;

            if (p)
                *p = ptr;

            return true;
        }
    }

    return false;
}

bool
StringToInt64(const char *s, int64_t &result, const char **p, int base)
{
    if (s) {
        char *ptr = 0;
        const int64_t h = (int64_t) strtoll(s, &ptr, base);

        if (ptr != s && ptr) {
            result = h;

            if (p)
                *p = ptr;

            return true;
        }
    }

    return false;
}
