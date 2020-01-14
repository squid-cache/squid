/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "strnrchr.h"

const char *
strnrchr(const char *s, size_t count, int c)
{
    const char *rv=NULL;
    const char *l=s;
    while (count > 0 && *l != 0) {
        if (*l==c)
            rv=l;
        ++l;
        --count;
    }
    return rv;
}

