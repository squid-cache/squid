
/*
 * $Id: referer.cc,v 1.1 2000/07/13 06:13:43 wessels Exp $
 *
 * DEBUG: section 40    User-Agent and Referer logging
 * AUTHOR: Joe Ramey <ramey@csc.ti.com> (useragent)
 *         Jens-S. Vöckler <voeckler@rvs.uni-hannover.de> (mod 4 referer)
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
	debug(40, 1) ("Referer logging is disabled.\n");
	return;
    }
    logfileOpen(Config.Log.referer, 0);
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
