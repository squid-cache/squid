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
    // By default, std::random_device may be blocking or non-blocking, which is
    // implementation-defined, so we need "/dev/urandom" to guarantee the non-blocking
    // behavior. Theoretically, this file may be missing in some exotic
    // configurations, causing std::runtime_error. For simplicity, we assume that
    // such configurations do not exist until the opposite is confirmed.
    static std::random_device dev("/dev/urandom");
    return dev();
}

std::mt19937_64::result_type
Seed64()
{
    std::mt19937_64::result_type value = Seed32();
    return (value << 32) | Seed32();
}

