/*
 * DEBUG: section 03    Configuration File Parsing
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
#include "cache_cf.h"
#include "compat/strtoll.h"
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

int64_t
GetInteger64(void)
{
    char *token = strtok(NULL, w_space);
    int64_t i;

    if (token == NULL)
        self_destruct();

    i = strtoll(token, NULL, 10);

    return i;
}

int
GetInteger(void)
{
    char *token = strtok(NULL, w_space);
    int i;

    if (token == NULL)
        self_destruct();

    // %i honors 0 and 0x prefixes, which are important for things like umask
    if (sscanf(token, "%i", &i) != 1)
        self_destruct();

    return i;
}

unsigned short
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

bool
GetHostWithPort(char *token, Ip::Address *ipa)
{
    char *t;
    char *host;
    char *tmp;
    unsigned short port;

    host = NULL;
    port = 0;

    if (*token == '[') {
        /* [host]:port */
        host = token + 1;
        t = strchr(host, ']');
        if (!t)
            return false;
        *t = '\0';
        ++t;
        if (*t != ':')
            return false;
        port = xatos(t + 1);
    } else if ((t = strchr(token, ':'))) {
        /* host:port */
        host = token;
        *t = '\0';
        port = xatos(t + 1);

        if (0 == port)
            return false;
    } else if ((port = strtol(token, &tmp, 10)), !*tmp) {
        /* port */
    } else {
        host = token;
        port = 0;
    }

    if (NULL == host)
        ipa->SetAnyAddr();
    else if ( ipa->GetHostByName(host) ) /* dont use ipcache. Accept either FQDN or IPA. */
        (void) 0;
    else
        return false;

    /* port MUST be set after the IPA lookup/conversion is performed. */
    ipa->SetPort(port);

    return true;
}
