/*
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
#include "squid.h"
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

int
tvSubMsec(struct timeval t1, struct timeval t2)
{
    return (t2.tv_sec - t1.tv_sec) * 1000 +
           (t2.tv_usec - t1.tv_usec) / 1000;
}

TimeEngine::~TimeEngine()
{}

void
TimeEngine::tick()
{
    getCurrentTime();
}

const char *
Time::FormatStrf(time_t t)
{
    struct tm *tm;
    static char buf[128];
    static time_t last_t = 0;

    if (t != last_t) {
        tm = localtime(&t);
        strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
        last_t = t;
    }

    return buf;
}

const char *
Time::FormatHttpd(time_t t)
{
    static char buf[128];
    static time_t last_t = 0;

    if (t != last_t) {
        struct tm *gmt = gmtime(&t);

#if !USE_GMT
        int gmt_min, gmt_hour, gmt_yday, day_offset;
        size_t len;
        struct tm *lt;
        int min_offset;

        /* localtime & gmtime may use the same static data */
        gmt_min = gmt->tm_min;
        gmt_hour = gmt->tm_hour;
        gmt_yday = gmt->tm_yday;

        lt = localtime(&t);

        day_offset = lt->tm_yday - gmt_yday;
        /* wrap round on end of year */
        if (day_offset > 1)
            day_offset = -1;
        else if (day_offset < -1)
            day_offset = 1;

        min_offset = day_offset * 1440 + (lt->tm_hour - gmt_hour) * 60
                     + (lt->tm_min - gmt_min);

        len = strftime(buf, 127 - 5, "%d/%b/%Y:%H:%M:%S ", lt);
        snprintf(buf + len, 128 - len, "%+03d%02d",
                 (min_offset / 60) % 24,
                 min_offset % 60);
#else /* USE_GMT */
        buf[0] = '\0';
        strftime(buf, 127, "%d/%b/%Y:%H:%M:%S -000", gmt);
#endif /* USE_GMT */

        last_t = t;
    }

    return buf;
}
