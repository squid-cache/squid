/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#include "squid.h"
#include "cache_cf.h"
#include "compat/strtoll.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "globals.h"
#include "Parsing.h"

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
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return -1; // not reachable
    }

    return xatoll(token, 10);
}

/*
 * This function is different from others (e.g., GetInteger64, GetShort)
 * because it supports octal and hexadecimal numbers
 */
int
GetInteger(void)
{
    char *token = ConfigParser::NextToken();
    int i;

    if (!token) {
        self_destruct();
        return -1; // not reachable
    }

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
 * unless the limit parameter is set to false.
 */
double
GetPercentage(bool limit)
{
    char *token = ConfigParser::NextToken();

    if (!token) {
        debugs(3, DBG_CRITICAL, "FATAL: A percentage value is missing.");
        self_destruct();
        return 0.0; // not reachable
    }

    //if there is a % in the end of the digits, we remove it and go on.
    char* end = &token[strlen(token)-1];
    if (*end == '%') {
        *end = '\0';
    }

    int p = xatoi(token);

    if (p < 0 || (limit && p > 100)) {
        debugs(3, DBG_CRITICAL, "FATAL: The value '" << token << "' is out of range. A percentage should be within [0, 100].");
        self_destruct();
    }

    return static_cast<double>(p) / 100.0;
}

unsigned short
GetShort(void)
{
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return 0; // not reachable
    }

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

