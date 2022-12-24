/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 09    File Transfer Protocol (FTP) */

#include "squid.h"
#include "ftp/Parsing.h"
#include "ip/Address.h"
#include "MemBuf.h"
#include "SquidConfig.h"

bool
Ftp::ParseIpPort(const char *buf, const char *forceIp, Ip::Address &addr)
{
    int h1, h2, h3, h4;
    int p1, p2;
    const int n = sscanf(buf, "%d,%d,%d,%d,%d,%d",
                         &h1, &h2, &h3, &h4, &p1, &p2);

    if (n != 6 || p1 < 0 || p2 < 0 || p1 > 255 || p2 > 255)
        return false;

    if (forceIp) {
        addr = forceIp; // but the above code still validates the IP we got
    } else {
        static char ipBuf[1024];
        snprintf(ipBuf, sizeof(ipBuf), "%d.%d.%d.%d", h1, h2, h3, h4);
        addr = ipBuf;

        if (addr.isAnyAddr())
            return false;
    }

    const int port = ((p1 << 8) + p2);

    if (port <= 0)
        return false;

    if (Config.Ftp.sanitycheck && port < 1024)
        return false;

    addr.port(port);
    return true;
}

bool
Ftp::ParseProtoIpPort(const char *buf, Ip::Address &addr)
{

    const char delim = *buf;
    const char *s = buf + 1;
    const char *e = s;
    const int proto = strtol(s, const_cast<char**>(&e), 10);
    if ((proto != 1 && proto != 2) || *e != delim)
        return false;

    s = e + 1;
    e = strchr(s, delim);
    char ip[MAX_IPSTRLEN];
    if (static_cast<size_t>(e - s) >= sizeof(ip))
        return false;
    strncpy(ip, s, e - s);
    ip[e - s] = '\0';
    addr = ip;

    if (addr.isAnyAddr())
        return false;

    if ((proto == 2) != addr.isIPv6()) // proto ID mismatches address version
        return false;

    s = e + 1; // skip port delimiter
    const int port = strtol(s, const_cast<char**>(&e), 10);
    if (port < 0 || *e != '|')
        return false;

    if (Config.Ftp.sanitycheck && port < 1024)
        return false;

    addr.port(port);
    return true;
}

const char *
Ftp::UnescapeDoubleQuoted(const char *quotedPath)
{
    static MemBuf path;
    path.reset();
    const char *s = quotedPath;
    if (*s == '"') {
        ++s;
        bool parseDone = false;
        while (!parseDone) {
            if (const char *e = strchr(s, '"')) {
                path.append(s, e - s);
                s = e + 1;
                if (*s == '"') {
                    path.append(s, 1);
                    ++s;
                } else
                    parseDone = true;
            } else { //parse error
                parseDone = true;
                path.reset();
            }
        }
    }
    return path.content();
}

