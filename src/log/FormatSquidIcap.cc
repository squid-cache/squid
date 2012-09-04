/*
 * DEBUG: section 46    Access Log - Squid ICAP Logging
 * AUTHOR: Alex Rousskov
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

#if ICAP_CLIENT

#include "AccessLogEntry.h"
#include "format/Quoting.h"
#include "fqdncache.h"
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidConfig.h"
#include "SquidTime.h"

void
Log::Format::SquidIcap(const AccessLogEntry::Pointer &al, Logfile * logfile)
{
    const char *client = NULL;
    const char *user = NULL;
    char tmp[MAX_IPSTRLEN], clientbuf[MAX_IPSTRLEN];

    if (al->cache.caddr.IsAnyAddr()) { // ICAP OPTIONS xactions lack client
        client = "-";
    } else {
        if (Config.onoff.log_fqdn)
            client = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);
        if (!client)
            client = al->cache.caddr.NtoA(clientbuf, MAX_IPSTRLEN);
    }

    user = ::Format::QuoteUrlEncodeUsername(al->cache.authuser);

    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.extuser);

#if USE_SSL
    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.ssluser);
#endif

    if (!user)
        user = ::Format::QuoteUrlEncodeUsername(al->cache.rfc931);

    if (user && !*user)
        safe_free(user);

    logfilePrintf(logfile, "%9ld.%03d %6d %s %s/%03d %" PRId64 " %s %s %s -/%s -\n",
                  (long int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  al->icap.trTime,
                  client,
                  al->icap.outcome,
                  al->icap.resStatus,
                  al->icap.bytesRead,
                  Adaptation::Icap::ICAP::methodStr(al->icap.reqMethod),
                  al->icap.reqUri.termedBuf(),
                  user ? user : "-",
                  al->icap.hostAddr.NtoA(tmp, MAX_IPSTRLEN));
    safe_free(user);
}
#endif
