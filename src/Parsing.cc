/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration File Parsing */

#include "squid.h"
#include "cache_cf.h"
#include "cfg/Exceptions.h"
#include "compat/strtoll.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "globals.h"
#include "Parsing.h"

/*
 * These functions is the same as atoi/l/f, except that they check for errors
 */

double
xatof(const char *token)
{
    char *end = nullptr;
    double ret = strtod(token, &end);

    if (ret == 0 && end == token)
        throw Cfg::FatalError(ToSBuf("no digits were found in the input value '", token, "'"));

    if (*end)
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is supposed to be a number"));

    return ret;
}

int
xatoi(const char *token)
{
    int64_t input = xatoll(token, 10);
    int ret = (int) input;

    if (input != static_cast<int64_t>(ret))
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is larger than the type 'int'"));

    return ret;
}

unsigned int
xatoui(const char *token, char eov)
{
    int64_t input = xatoll(token, 10, eov);
    if (input < 0)
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' cannot be less than 0"));

    unsigned int ret = (unsigned int) input;
    if (input != static_cast<int64_t>(ret))
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is larger than the type 'unsigned int'"));

    return ret;
}

long
xatol(const char *token)
{
    int64_t input = xatoll(token, 10);
    long ret = (long) input;

    if (input != static_cast<int64_t>(ret))
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is larger than the type 'long'"));

    return ret;
}

int64_t
xatoll(const char *token, int base, char eov)
{
    char *end = nullptr;
    int64_t ret = strtoll(token, &end, base);

    if (end == token)
        throw Cfg::FatalError(ToSBuf("invalid value: no digits were found in '", token, "'"));

    if (*end != eov)
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is supposed to be a number"));

    return ret;
}

uint64_t
xatoull(const char *token, int base, char eov)
{
    const auto number = xatoll(token, base, eov);
    if (number < 0)
        throw TextException(ToSBuf("the input value '", token, "' cannot be less than 0"), Here());
    return static_cast<uint64_t>(number);
}

unsigned short
xatos(const char *token)
{
    long port = xatol(token);

    if (port < 0)
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' cannot be less than 0"));

    if ((port & ~0xFFFF) != 0)
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is larger than the type 'short'"));

    return port;
}

int64_t
GetInteger64(void)
{
    char *token = ConfigParser::NextToken();
    if (!token)
        throw Cfg::FatalError("number is missing");

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
    if (!token)
        throw Cfg::FatalError("number is missing");

    // The conversion must honor 0 and 0x prefixes, which are important for things like umask
    int64_t ret = xatoll(token, 0);

    int i = (int) ret;
    if (ret != static_cast<int64_t>(i))
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is larger than the type 'int'"));

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
    if (!token)
        throw Cfg::FatalError("percentage value is missing");

    //if there is a % in the end of the digits, we remove it and go on.
    char* end = &token[strlen(token)-1];
    if (*end == '%') {
        *end = '\0';
    }

    int p = xatoi(token);
    if (p < 0 || (limit && p > 100))
        throw Cfg::FatalError(ToSBuf("invalid value: '", token, "' is out of range. A percentage should be within [0, 100]."));

    return static_cast<double>(p) / 100.0;
}

unsigned short
GetShort(void)
{
    char *token = ConfigParser::NextToken();
    if (!token)
        throw Cfg::FatalError("number value is missing");
    return xatos(token);
}

bool
StringToInt(const char *s, int &result, const char **p, int base)
{
    if (s) {
        char *ptr = nullptr;
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
        char *ptr = nullptr;
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

    host = nullptr;
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

    if (nullptr == host)
        ipa->setAnyAddr();
    else if (ipa->GetHostByName(host)) /* do not use ipcache. Accept either FQDN or IPA. */
        (void) 0;
    else
        return false;

    /* port MUST be set after the IPA lookup/conversion is performed. */
    ipa->port(port);

    return true;
}

