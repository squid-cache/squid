/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "xusleep.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/**
 * xusleep, as usleep but accepts longer pauses
 */
int
xusleep(unsigned int usec)
{
    /* XXX emulation of usleep() */
    struct timeval sl;
    sl.tv_sec = usec / 1000000;
    sl.tv_usec = usec % 1000000;
    return select(0, NULL, NULL, NULL, &sl);
}

