/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/debug.h"

/* default off */
int debug_enabled = 0;

#ifndef __GNUC__
/* under gcc a macro define in compat/debug.h is used instead */

void
debug(const char *format,...)
{
    if (!debug_enabled)
        return;
    va_list args;
    va_start (args,format);
    vfprintf(stderr,format,args);
    va_end(args);
}

#endif /* __GNUC__ */

