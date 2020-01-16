/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if HAVE_ASSERT_H
#include <assert.h>
#endif

int
main(int argc, char *argv[])
{
    int i;
    struct timeval now;
    struct timeval alarm;
    struct timeval to;
    assert(argc == 2);
    i = atoi(argv[1]);
    gettimeofday(&now, NULL);
    alarm.tv_sec = now.tv_sec + i + (now.tv_sec % i);
    alarm.tv_usec = 0;
    to.tv_sec = alarm.tv_sec - now.tv_sec;
    to.tv_usec = alarm.tv_usec - now.tv_usec;
    if (to.tv_usec < 0) {
        to.tv_usec += 1000000;
        to.tv_sec -= 1;
    }
    select(1, NULL, NULL, NULL, &to);
    return 0;
}

