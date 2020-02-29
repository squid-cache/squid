/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* Stub function for programs not implementing statMemoryAccounted */
#include "squid.h"
#include "util.h"

int
statMemoryAccounted(void)
{
    return -1;
}

