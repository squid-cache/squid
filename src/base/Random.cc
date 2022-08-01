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
    // We promise entropy collection without waiting, but there is no standard
    // way to get that in all environments:
    // * GCC and clang use "/dev/urandom" device name by default.
    // * GCC throws if the requested "/dev/urandom" is not supported.
    // * clang implementations that use getentropy(3) throw if given any device
    //   name other than "/dev/urandom".
    // * clang implementations that use (non-waiting entropy collection provided
    //   by) arc4random(3) ignore the device name.
    // * Microsoft STL ignores the device name and is silent regarding entropy
    //   collection wait but talks about being "slower" than pseudo r.n.g. and
    //   doing blocking I/O, implying entropy source similar to "/dev/urandom".
    //
    // Since popular STL implementations gravitate towards non-blocking entropy
    // collection, we assume that all other implementations (that Squid may
    // encounter) will mimic that popular default. We could insist on
    // "/dev/urandom" (and fall back to default on exceptions) instead, but that
    // might prevent an implementation from selecting a "better" entropy source
    // (than "/dev/urandom") and increase cache.log notification noise.
    static std::random_device dev;
    return dev();
}

std::mt19937_64::result_type
Seed64()
{
    std::mt19937_64::result_type value = Seed32();
    return (value << 32) | Seed32();
}

