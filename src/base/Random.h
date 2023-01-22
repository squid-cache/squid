/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_RANDOM_H
#define SQUID_SRC_BASE_RANDOM_H

#include <random>

/// A 32-bit random value suitable for seeding a 32-bit random number generator.
/// Computing this value may require blocking device I/O but does not require
/// waiting to accumulate entropy. Thus, this function:
/// * may be called at runtime (e.g., the first time a given r.n.g. is needed)
/// * should not be called frequently (e.g., once per transaction is too often)
/// * should not be used as a source of randomness (use a r.n.g. instead)
std::mt19937::result_type RandomSeed32();

/// a 64-bit version of RandomSeed32()
std::mt19937_64::result_type RandomSeed64();

#endif /* SQUID_SRC_BASE_RANDOM_H */

