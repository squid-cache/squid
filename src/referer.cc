
/*
 * $Id: referer.cc,v 1.9 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 40    Referer Logging
 * AUTHOR: Joe Ramey <ramey@csc.ti.com> (useragent)
 *         Jens-S. Vöckler <voeckler@rvs.uni-hannover.de> (mod 4 referer)
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

#if USE_REFERER_LOG
static Logfile *refererlog = NULL;
#endif

void
refererOpenLog(void)
{
#if USE_REFERER_LOG
    assert(NULL == refererlog);

    if (!Config.Log.referer || (0 == strcmp(Config.Log.referer, "none"))) {
        debugs(40, 1, "Referer logging is disabled.");
        return;
    }

    refererlog = logfileOpen(Config.Log.referer, 0, 1);
#endif
}

void
refererRotateLog(void)
{
#if USE_REFERER_LOG

    if (NULL == refererlog)
        return;

    logfileRotate(refererlog);

#endif
}

void
logReferer(const char *client, const char *referer, const char *uri)
{
#if USE_REFERER_LOG

    if (NULL == refererlog)
        return;

    logfilePrintf(refererlog, "%9d.%03d %s %s %s\n",
                  (int) current_time.tv_sec,
                  (int) current_time.tv_usec / 1000,
                  client,
                  referer,
                  uri ? uri : "-");

#endif
}

void
refererCloseLog(void)
{
#if USE_REFERER_LOG

    if (NULL == refererlog)
        return;

    logfileClose(refererlog);

    refererlog = NULL;

#endif
}
