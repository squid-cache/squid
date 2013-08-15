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
#include "ConfigParser.h"
#include "Parsing.h"
#include "globals.h"
#include "Debug.h"

/*
 * These functions is the same as atoi/l/f, except that they check for errors
 */

double
xatof(const char *token)
{
    char *end = NULL;
    double ret = strtod(token, &end);

    if (ret == 0 && end == token) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: No digits were found in the input value '" << token << "'.");
        self_destruct();
    }

    if (*end) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Invalid value: '" << token << "' is supposed to be a number.");
        self_destruct();
    }

    return ret;
}

int
xatoi(const char *token)
{
    int64_t input = xatoll(token, 10);
    int ret = (int) input;

    if (input != static_cast<int64_t>(ret)) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' is larger than the type 'int'.");
        self_destruct();
    }

    return ret;
}

unsigned int
xatoui(const char *token, char eov)
{
    int64_t input = xatoll(token, 10, eov);
    if (input < 0) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The input value '" << token << "' cannot be less than 0.");
        self_destruct();
    }

    unsigned int ret = (unsigned int) input;
    if (input != static_cast<int64_t>(ret)) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' is larger than the type 'unsigned int'.");
        self_destruct();
    }

    return ret;
}

long
xatol(const char *token)
{
    int64_t input = xatoll(token, 10);
    long ret = (long) input;

    if (input != static_cast<int64_t>(ret)) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' is larger than the type 'long'.");
        self_destruct();
    }

    return ret;
}

int64_t
xatoll(const char *token, int base, char eov)
{
    char *end = NULL;
    int64_t ret = strtoll(token, &end, base);

    if (end == token) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: No digits were found in the input value '" << token << "'.");
        self_destruct();
    }

    if (*end != eov) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Invalid value: '" << token << "' is supposed to be a number.");
        self_destruct();
    }

    return ret;
}

unsigned short
xatos(const char *token)
{
    long port = xatol(token);

    if (port < 0) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' cannot be less than 0.");
        self_destruct();
    }

    if (port & ~0xFFFF) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' is larger than the type 'short'.");
        self_destruct();
    }

    return port;
}

int64_t
GetInteger64(void)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
        self_destruct();

    return xatoll(token, 10);
}

/*
 * This function is different from others (e.g., GetInteger64, GetShort)
 * because it supports octal and hexadecimal numbers
 */
int
GetInteger(void)
{
    char *token = ConfigParser::strtokFile();
    int i;

    if (token == NULL)
        self_destruct();

    // The conversion must honor 0 and 0x prefixes, which are important for things like umask
    int64_t ret = xatoll(token, 0);

    i = (int) ret;
    if (ret != static_cast<int64_t>(i)) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' is larger than the type 'int'.");
        self_destruct();
    }

    return i;
}

/*
 * This function is similar as GetInteger() but the token might contain
 * the percentage symbol (%) and we check whether the value is in the range
 * of [0, 100]
 * So, we accept two types of input: 1. XX% or 2. XX , 0<=XX<=100
 */
int
GetPercentage(void)
{
    int p;
    char *token = strtok(NULL, w_space);

    if (!token) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: A percentage value is missing.");
        self_destruct();
    }

    //if there is a % in the end of the digits, we remove it and go on.
    char* end = &token[strlen(token)-1];
    if (*end == '%') {
        *end = '\0';
    }

    p = xatoi(token);

    if (p < 0 || p > 100) {
        debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: The value '" << token << "' is out of range. A percentage should be within [0, 100].");
        self_destruct();
    }

    return p;
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
    } else if (strtol(token, &tmp, 10) && !*tmp) {
        port = xatos(token);
    } else {
        host = token;
        port = 0;
    }

    if (NULL == host)
        ipa->setAnyAddr();
    else if ( ipa->GetHostByName(host) ) /* dont use ipcache. Accept either FQDN or IPA. */
        (void) 0;
    else
        return false;

    /* port MUST be set after the IPA lookup/conversion is performed. */
    ipa->port(port);

    return true;
}
