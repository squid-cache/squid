/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 21    Integer functions */

#include "squid.h"

#include <cmath>

int
isPowTen(int count)
{
    double x = log(static_cast<double>(count)) / log(10.0);

    if (0.0 != x - (double) (int) x)
        return 0;

    return 1;
}

