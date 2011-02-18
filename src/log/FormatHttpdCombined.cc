/*
 * $Id$
 *
 * DEBUG: section 46    Access Log - Apache combined format
 * AUTHOR: Amos Jeffries
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
#include "HttpRequest.h"
#include "log/File.h"
#include "log/Formats.h"
#include "log/Gadgets.h"
#include "log/Tokens.h"
#include "SquidTime.h"

void
Log::Format::HttpdCombined(AccessLogEntry * al, Logfile * logfile)
{
    char clientip[MAX_IPSTRLEN];

    const char *user_ident = FormatName(al->cache.rfc931);

    const char *user_auth = FormatName(al->cache.authuser);

    const char *referer = al->request->header.getStr(HDR_REFERER);
    if (!referer || *referer == '\0')
        referer = "-";

    const char *agent = al->request->header.getStr(HDR_USER_AGENT);
    if (!agent || *agent == '\0')
        agent = "-";

    logfilePrintf(logfile, "%s %s %s [%s] \"%s %s HTTP/%d.%d\" %d %"PRId64" \"%s\" \"%s\" %s%s:%s%s",
                  al->cache.caddr.NtoA(clientip,MAX_IPSTRLEN),
                  user_ident ? user_ident : dash_str,
                  user_auth ? user_auth : dash_str,
                  Time::FormatHttpd(squid_curtime),
                  al->_private.method_str,
                  al->url,
                  al->http.version.major, al->http.version.minor,
                  al->http.code,
                  al->cache.replySize,
                  referer,
                  agent,
                  log_tags[al->cache.code],
                  al->http.statusSfx(),
                  hier_code_str[al->hier.code],
                  (Config.onoff.log_mime_hdrs?"":"\n"));

    safe_free(user_ident);
    safe_free(user_auth);

    if (Config.onoff.log_mime_hdrs) {
        char *ereq = QuoteMimeBlob(al->headers.request);
        char *erep = QuoteMimeBlob(al->headers.reply);
        logfilePrintf(logfile, " [%s] [%s]\n", ereq, erep);
        safe_free(ereq);
        safe_free(erep);
    }
}
