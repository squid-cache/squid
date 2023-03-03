/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Random.h"

std::mt19937::result_type
RandomSeed32()
{
    // We promise entropy collection without waiting, but there is no standard
    // way to get that in all environments. We considered these device names:
    //
    // * none: The default constructor in some specialized STL implementation or
    //   build might select a device that requires Squid to wait for entropy.
    //
    // * "default": Leads to clang (and other STLs) exceptions in some builds
    //   (e.g., when clang is built to use getentropy(3) or rand_s()).
    //
    // * "/dev/urandom": Blocks GCC from picking the best entropy source (e.g.,
    //   arc4random(3)) and leads to GCC/clang exceptions in some environments.
    //
    // If a special supported environment needs a non-default device name, we
    // will add a random_device_name configuration directive. We cannot detect
    // such needs in general code and choose to write simpler code until then.
    static std::random_device dev;
    return dev();
}

std::mt19937_64::result_type
RandomSeed64()
{
    std::mt19937_64::result_type left = RandomSeed32();
    return (left << 32) | RandomSeed32();
}

