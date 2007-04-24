#include "config.h"
#include "profiling.h"
#include "xusleep.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif


/*
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
