/*
 * $Id$
 *
 * DEBUG: section 21    Time Functions
 * AUTHOR: Harvest Derived
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

#include "SquidTime.h"

struct timeval current_time;
double current_dtime;

time_t squid_curtime = 0;

time_t
getCurrentTime(void)
{
#if GETTIMEOFDAY_NO_TZP
    gettimeofday(&current_time);
#else

    gettimeofday(&current_time, NULL);
#endif

    current_dtime = (double) current_time.tv_sec +
                    (double) current_time.tv_usec / 1000000.0;
    return squid_curtime = current_time.tv_sec;
}

TimeEngine::~TimeEngine()
{}

void
TimeEngine::tick()
{
    getCurrentTime();
}
