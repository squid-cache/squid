/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

void xassert(const char *expr, const char *file, int line)
{
    fprintf(stderr, "assertion failed: %s:%d: \"%s\"\n", file, line, expr);
    abort();
}

