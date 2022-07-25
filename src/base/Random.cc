/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "base/Random.h"

std::mt19937::result_type
Seed32()
{
    static_assert(sizeof(std::random_device::result_type) == 4, "std::random_device generates a 4-byte number");
    static std::random_device dev;
    return dev();
}

std::mt19937_64::result_type
Seed64()
{
    std::mt19937_64::result_type value = Seed32();
    return (value << 32) | Seed32();
}

