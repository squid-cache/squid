/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif

extern int sys_nerr;

#if NEED_SYS_ERRLIST
extern char *sys_errlist[];
#endif

char *
strerror(int ern)
{
    return sys_errlist[ern];
}

