
/*
 * $Id: rfc1123.c,v 1.23 1999/04/15 06:15:38 wessels Exp $
 *
 * DEBUG: 
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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


/*
 *  Adapted from HTSUtils.c in CERN httpd 3.0 (http://info.cern.ch/httpd/)
 *  by Darren Hardy <hardy@cs.colorado.edu>, November 1994.
 */
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "util.h"
#include "snprintf.h"

#define RFC850_STRFTIME "%A, %d-%b-%y %H:%M:%S GMT"
#define RFC1123_STRFTIME "%a, %d %b %Y %H:%M:%S GMT"

static int make_month(const char *s);
static int make_num(const char *s);

static char *month_names[12] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


static int
make_num(const char *s)
{
    if (*s >= '0' && *s <= '9')
	return 10 * (*s - '0') + *(s + 1) - '0';
    else
	return *(s + 1) - '0';
}

static int
make_month(const char *s)
{
    int i;
    char month[3];

    month[0] = xtoupper(*s);
    month[1] = xtolower(*(s + 1));
    month[2] = xtolower(*(s + 2));

    for (i = 0; i < 12; i++)
	if (!strncmp(month_names[i], month, 3))
	    return i;
    return 0;
}


time_t
parse_rfc1123(const char *str)
{
    const char *s;
    struct tm tm;
    time_t t;

    if (!str)
	return -1;

    memset(&tm, '\0', sizeof(struct tm));
    if ((s = strchr(str, ','))) {	/* Thursday, 10-Jun-93 01:29:59 GMT */
	s++;			/* or: Thu, 10 Jan 1993 01:29:59 GMT */
	while (*s == ' ')
	    s++;
	if (xisdigit(*s) && !xisdigit(*(s + 1)))	/* backoff if only one digit */
	    s--;
	if (strchr(s, '-')) {	/* First format */
	    if ((int) strlen(s) < 18)
		return -1;
	    tm.tm_mday = make_num(s);
	    tm.tm_mon = make_month(s + 3);
	    tm.tm_year = make_num(s + 7);
	    /*
	     * Y2K: Arjan de Vet <Arjan.deVet@adv.IAEhv.nl>
	     * if tm.tm_year < 70, assume it's after the year 2000.
	     */
	    if (tm.tm_year < 70)
		tm.tm_year += 100;
	    tm.tm_hour = make_num(s + 10);
	    tm.tm_min = make_num(s + 13);
	    tm.tm_sec = make_num(s + 16);
	} else {		/* Second format */
	    if ((int) strlen(s) < 20)
		return -1;
	    tm.tm_mday = make_num(s);
	    tm.tm_mon = make_month(s + 3);
	    tm.tm_year = (100 * make_num(s + 7) - 1900) + make_num(s + 9);
	    tm.tm_hour = make_num(s + 12);
	    tm.tm_min = make_num(s + 15);
	    tm.tm_sec = make_num(s + 18);

	}
    } else {			/* Try the other format:        */
	s = str;		/* Wed Jun  9 01:29:59 1993 GMT */
	while (*s && *s == ' ')
	    s++;
	if ((int) strlen(s) < 24)
	    return -1;
	tm.tm_mday = make_num(s + 8);
	tm.tm_mon = make_month(s + 4);
	/* Y2K fix, richard.kettlewell@kewill.com */
	tm.tm_year = atoi(s + 20) - 1900;
	tm.tm_hour = make_num(s + 11);
	tm.tm_min = make_num(s + 14);
	tm.tm_sec = make_num(s + 17);
    }
    if (tm.tm_sec < 0 || tm.tm_sec > 59 ||
	tm.tm_min < 0 || tm.tm_min > 59 ||
	tm.tm_hour < 0 || tm.tm_hour > 23 ||
	tm.tm_mday < 1 || tm.tm_mday > 31 ||
	tm.tm_mon < 0 || tm.tm_mon > 11 ||
	tm.tm_year < 70 || tm.tm_year > 120) {
	return -1;
    }
    tm.tm_isdst = -1;

#ifdef HAVE_TIMEGM
    t = timegm(&tm);
#elif HAVE_TM_GMTOFF
    t = mktime(&tm);
    {
	struct tm *local = localtime(&t);
	t += local->tm_gmtoff;
    }
#else
    /* some systems do not have tm_gmtoff so we fake it */
    t = mktime(&tm);
    {
	time_t dst = 0;
#if defined (_TIMEZONE)
#elif defined (_timezone)
#elif defined(_SQUID_AIX_)
#else
	extern time_t timezone;
#endif
	/*
	 * The following assumes a fixed DST offset of 1 hour,
	 * which is probably wrong.
	 */
	if (tm.tm_isdst > 0)
	    dst = -3600;
#ifdef _timezone
	t -= (_timezone + dst);
#else
	t -= (timezone + dst);
#endif
    }
#endif
    return t;
}

const char *
mkrfc1123(time_t t)
{
    static char buf[128];

    struct tm *gmt = gmtime(&t);

    buf[0] = '\0';
    strftime(buf, 127, RFC1123_STRFTIME, gmt);
    return buf;
}

const char *
mkhttpdlogtime(const time_t * t)
{
    static char buf[128];

    struct tm *gmt = gmtime(t);

#ifndef USE_GMT
    int gmt_min, gmt_hour, gmt_yday, day_offset;
    size_t len;
    struct tm *lt;
    int min_offset;

    /* localtime & gmtime may use the same static data */
    gmt_min = gmt->tm_min;
    gmt_hour = gmt->tm_hour;
    gmt_yday = gmt->tm_yday;

    lt = localtime(t);

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

    return buf;
}

#if 0
int
main()
{
    char *x;
    time_t t, pt;

    t = time(NULL);
    x = mkrfc1123(t);
    printf("HTTP Time: %s\n", x);

    pt = parse_rfc1123(x);
    printf("Parsed: %d vs. %d\n", pt, t);
}

#endif
