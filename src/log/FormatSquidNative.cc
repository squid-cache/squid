/*
 * $Id$
 *
 * DEBUG: section 46    Access Log - Squid format
 * AUTHOR: Duane Wessels
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

#include "config.h"
#include "AccessLogEntry.h"
#include "log/File.h"
#include "log/Formats.h"
#include "log/Gadgets.h"
#include "log/Tokens.h"
#include "SquidTime.h"

void
Log::Format::SquidNative(AccessLogEntry * al, Logfile * logfile)
{
    const char *user = NULL;
    char clientip[MAX_IPSTRLEN];

    user = FormatName(al->cache.authuser);

    if (!user)
        user = FormatName(al->cache.extuser);

#if USE_SSL
    if (!user)
        user = FormatName(al->cache.ssluser);
#endif

    if (!user)
        user = FormatName(al->cache.rfc931);

    if (user && !*user)
        safe_free(user);

    logfilePrintf(logfile, "%9ld.%03d %6d %s %s%s/%03d %"PRId64" %s %s %s %s%s/%s %s%s",
                  (long int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  al->cache.msec,
                  al->cache.caddr.NtoA(clientip, MAX_IPSTRLEN),
                  log_tags[al->cache.code],
                  al->http.statusSfx(),
                  al->http.code,
                  al->cache.replySize,
                  al->_private.method_str,
                  al->url,
                  user ? user : dash_str,
                  al->hier.ping.timedout ? "TIMEOUT_" : "",
                  hier_code_str[al->hier.code],
                  al->hier.host,
                  al->http.content_type,
                  (Config.onoff.log_mime_hdrs?"":"\n"));

    safe_free(user);

    if (Config.onoff.log_mime_hdrs) {
        char *ereq = QuoteMimeBlob(al->headers.request);
        char *erep = QuoteMimeBlob(al->headers.reply);
        logfilePrintf(logfile, " [%s] [%s]\n", ereq, erep);
        safe_free(ereq);
        safe_free(erep);
    }
}
