
/*
 * $Id: useragent.cc,v 1.21 2000/06/21 20:34:37 hno Exp $
 *
 * DEBUG: section 40    User-Agent logging
 * AUTHOR: Joe Ramey <ramey@csc.ti.com>
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

#if USE_USERAGENT_LOG
static Logfile *useragentlog = NULL;
#endif

void
useragentOpenLog(void)
{
#if USE_USERAGENT_LOG
    assert(NULL == useragentlog);
    if (!Config.Log.useragent || (0 == strcmp(Config.Log.useragent, "none"))) {
	debug(40, 1) ("User-Agent logging is disabled.\n");
	return;
    }
    logfileOpen(Config.Log.useragent, 0);
#endif
}

void
useragentRotateLog(void)
{
#if USE_USERAGENT_LOG
    if (NULL == useragentlog)
	return;
    logfileRotate(useragentlog);
#endif
}

void
logUserAgent(const char *client, const char *agent)
{
#if USE_USERAGENT_LOG
    static time_t last_time = 0;
    static char time_str[128];
    const char *s;
    if (NULL == useragentlog)
	return;
    if (squid_curtime != last_time) {
	s = mkhttpdlogtime(&squid_curtime);
	strcpy(time_str, s);
	last_time = squid_curtime;
    }
    logfilePrintf(useragentlog, "%s [%s] \"%s\"\n",
	client,
	time_str,
	agent);
#endif
}
