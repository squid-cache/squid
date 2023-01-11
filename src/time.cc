/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Time Functions */

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

void
tvSub(struct timeval &res, struct timeval const &t1, struct timeval const &t2)
{
    res.tv_sec = t2.tv_sec - t1.tv_sec;
    if (t2.tv_usec >= t1.tv_usec)
        res.tv_usec = t2.tv_usec - t1.tv_usec;
    else {
        res.tv_sec -= 1;
        res.tv_usec = t2.tv_usec + 1000000 - t1.tv_usec;
    }
}

void tvAdd(struct timeval &res, struct timeval const &t1, struct timeval const &t2)
{
    res.tv_sec = t1.tv_sec + t2.tv_sec;
    res.tv_usec = t1.tv_usec + t2.tv_usec;
    if (res.tv_usec >= 1000000) {
        ++res.tv_sec;
        res.tv_usec -= 1000000;
    }
}

void tvAssignAdd(struct timeval &t, struct timeval const &add)
{
    t.tv_sec += add.tv_sec;
    t.tv_usec += add.tv_usec;
    if (t.tv_usec >= 1000000) {
        ++t.tv_sec;
        t.tv_usec -= 1000000;
    }
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

