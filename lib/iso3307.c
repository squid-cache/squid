#include "squid.h"
#include "util.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif

#define ASCII_DIGIT(c) ((c)-48)

time_t
parse_iso3307_time(const char *buf)
{
    /* buf is an ISO 3307 style time: YYYYMMDDHHMMSS or YYYYMMDDHHMMSS.xxx */
    struct tm tms;
    time_t t;
    while (*buf == ' ' || *buf == '\t')
        buf++;
    if ((int) strlen(buf) < 14)
        return 0;
    memset(&tms, '\0', sizeof(struct tm));
    tms.tm_year = (ASCII_DIGIT(buf[0]) * 1000) + (ASCII_DIGIT(buf[1]) * 100) +
                  (ASCII_DIGIT(buf[2]) * 10) + ASCII_DIGIT(buf[3]) - 1900;
    tms.tm_mon = (ASCII_DIGIT(buf[4]) * 10) + ASCII_DIGIT(buf[5]) - 1;
    tms.tm_mday = (ASCII_DIGIT(buf[6]) * 10) + ASCII_DIGIT(buf[7]);
    tms.tm_hour = (ASCII_DIGIT(buf[8]) * 10) + ASCII_DIGIT(buf[9]);
    tms.tm_min = (ASCII_DIGIT(buf[10]) * 10) + ASCII_DIGIT(buf[11]);
    tms.tm_sec = (ASCII_DIGIT(buf[12]) * 10) + ASCII_DIGIT(buf[13]);
#if HAVE_TIMEGM
    t = timegm(&tms);
#elif HAVE_MKTIME
    t = mktime(&tms);
#else
    t = (time_t) 0;
#endif
    return t;
}
