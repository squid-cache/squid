
/*
 * $Id: rfc1123.c,v 1.29 2001/10/17 19:46:43 hno Exp $
 *
 * DEBUG: 
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
#include "assert.h"

#include "util.h"
#include "snprintf.h"

#define RFC850_STRFTIME "%A, %d-%b-%y %H:%M:%S GMT"
#define RFC1123_STRFTIME "%a, %d %b %Y %H:%M:%S GMT"

static const char *const w_space = " \t\r\n";

static int make_month(const char *s);
static int make_num(const char *s);

static const char *month_names[12] =
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

static int
tmSaneValues(struct tm *tm)
{
    if (tm->tm_sec < 0 || tm->tm_sec > 59)
	return 0;
    if (tm->tm_min < 0 || tm->tm_min > 59)
	return 0;
    if (tm->tm_hour < 0 || tm->tm_hour > 23)
	return 0;
    if (tm->tm_mday < 1 || tm->tm_mday > 31)
	return 0;
    if (tm->tm_mon < 0 || tm->tm_mon > 11)
	return 0;
    if (tm->tm_year < 70 || tm->tm_year > 120)
	return 0;
    return 1;
}

static struct tm *
parse_date1(const char *str)
{
    /* Thursday, 10-Jun-93 01:29:59 GMT */
    const char *s;
    static struct tm tm;
    assert(NULL != str);
    memset(&tm, '\0', sizeof(struct tm));
    s = strchr(str, ',');
    if (NULL == s)
	return NULL;
    s++;
    while (*s == ' ')
	s++;
    /* backup if month is only one digit */
    if (xisdigit(*s) && !xisdigit(*(s + 1)))
	s--;
    if (!strchr(s, '-'))
	return NULL;
    if ((int) strlen(s) < 18)
	return NULL;
    memset(&tm, '\0', sizeof(tm));
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
    return tmSaneValues(&tm) ? &tm : NULL;
}

static struct tm *
parse_date2(const char *str)
{
    /* Thu, 10 Jan 1993 01:29:59 GMT */
    const char *s;
    static struct tm tm;
    assert(NULL != str);
    memset(&tm, '\0', sizeof(struct tm));
    s = strchr(str, ',');
    if (NULL == s)
	return NULL;
    s++;
    while (*s == ' ')
	s++;
    /* backup if month is only one digit */
    if (xisdigit(*s) && !xisdigit(*(s + 1)))
	s--;
    if (strchr(s, '-'))
	return NULL;
    if ((int) strlen(s) < 20)
	return NULL;
    memset(&tm, '\0', sizeof(tm));
    tm.tm_mday = make_num(s);
    tm.tm_mon = make_month(s + 3);
    tm.tm_year = (100 * make_num(s + 7) - 1900) + make_num(s + 9);
    tm.tm_hour = make_num(s + 12);
    tm.tm_min = make_num(s + 15);
    tm.tm_sec = make_num(s + 18);
    return tmSaneValues(&tm) ? &tm : NULL;
}

static struct tm *
parse_date3(const char *str)
{
    /* Wed Jun  9 01:29:59 1993 GMT */
    static struct tm tm;
    char *s;
    static char buf[128];
    while (*str && *str == ' ')
	str++;
    xstrncpy(buf, str, 128);
    if (NULL == (s = strtok(buf, w_space)))
	return NULL;
    if (NULL == (s = strtok(NULL, w_space)))
	return NULL;
    tm.tm_mon = make_month(s);
    if (NULL == (s = strtok(NULL, w_space)))
	return NULL;
    tm.tm_mday = atoi(s);
    if (NULL == (s = strtok(NULL, ":")))
	return NULL;
    tm.tm_hour = atoi(s);
    if (NULL == (s = strtok(NULL, ":")))
	return NULL;
    tm.tm_min = atoi(s);
    if (NULL == (s = strtok(NULL, w_space)))
	return NULL;
    tm.tm_sec = atoi(s);
    if (NULL == (s = strtok(NULL, w_space)))
	return NULL;
    /* Y2K fix, richard.kettlewell@kewill.com */
    tm.tm_year = atoi(s) - 1900;
    return tmSaneValues(&tm) ? &tm : NULL;
}

time_t
parse_rfc1123(const char *str)
{
    struct tm *tm;
    time_t t;
    if (NULL == str)
	return -1;
    tm = parse_date1(str);
    if (NULL == tm) {
	tm = parse_date2(str);
	if (NULL == tm) {
	    tm = parse_date3(str);
	    if (NULL == tm)
		return -1;
	}
    }
    tm->tm_isdst = -1;
#ifdef HAVE_TIMEGM
    t = timegm(tm);
#elif HAVE_TM_GMTOFF
    t = mktime(tm);
    {
	struct tm *local = localtime(&t);
	t += local->tm_gmtoff;
    }
#else
    /* some systems do not have tm_gmtoff so we fake it */
    t = mktime(tm);
    {
	time_t dst = 0;
#if defined (_TIMEZONE)
#elif defined (_timezone)
#elif defined(_SQUID_AIX_)
#elif defined(_SQUID_CYGWIN_)
#else
	extern time_t timezone;
#endif
	/*
	 * The following assumes a fixed DST offset of 1 hour,
	 * which is probably wrong.
	 */
	if (tm->tm_isdst > 0)
	    dst = -3600;
#if defined ( _timezone) || defined(_SQUID_CYGWIN_)
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
