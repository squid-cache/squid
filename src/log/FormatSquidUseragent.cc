/*
 * $Id$
 *
 * DEBUG: section 46    Access Log - Squid useragent format
 * AUTHOR: Joe Ramey <ramey@csc.ti.com>
 * AUTHOR: Amos Jeffries <amosjeffries@squid-cache.org>
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
#include "SquidTime.h"

void
Log::Format::SquidUserAgent(AccessLogEntry * al, Logfile * logfile)
{
    char clientip[MAX_IPSTRLEN];

    const char *agent = al->request->header.getStr(HDR_USER_AGENT);

    // do not log unless there is something to be displayed.
    if (!agent || *agent == '\0')
        return;

    logfilePrintf(logfile, "%s [%s] \"%s\"\n",
                  al->cache.caddr.NtoA(clientip,MAX_IPSTRLEN),
                  Time::FormatHttpd(squid_curtime),
                  agent);
}
