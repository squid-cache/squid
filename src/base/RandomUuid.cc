/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "base/IoManip.h"
#include "base/RandomUuid.h"
#include "base/TextException.h"
#include "defines.h"

#include <iostream>
#include <random>

static_assert(sizeof(RandomUuid) == 128/8, "RandomUuid has RFC 4122-prescribed 128-bit size");

RandomUuid::RandomUuid()
{
    // Generate random bits for populating our UUID.
    // STL implementation bugs notwithstanding (e.g., MinGW bug #338), this is
    // our best chance of getting a non-deterministic seed value for the r.n.g.
    static std::mt19937_64 rng(std::random_device()); // produce 64-bit size values
    const auto rnd1 = rng();
    const auto rnd2 = rng();

    // bullet 3 of RFC 4122 Section 4.4 algorithm but setting _all_ bits (KISS)
    static_assert(sizeof(rnd1) + sizeof(rnd2) == sizeof(*this), "random bits fill a UUID");
    memcpy(raw(), &rnd1, sizeof(rnd1));
    memcpy(raw() + sizeof(rnd1), &rnd2, sizeof(rnd2));

    // bullet 1 of RFC 4122 Section 4.4 algorithm
    EBIT_CLR(clockSeqHiAndReserved, 6);
    EBIT_SET(clockSeqHiAndReserved, 7);

    // bullet 2 of RFC 4122 Section 4.4 algorithm
    EBIT_CLR(timeHiAndVersion, 13);
    EBIT_SET(timeHiAndVersion, 14);
    EBIT_CLR(timeHiAndVersion, 15);
    EBIT_CLR(timeHiAndVersion, 16);
}

RandomUuid::RandomUuid(const Serialized &bytes)
{
    static_assert(sizeof(*this) == sizeof(Serialized), "RandomUuid is deserialized with 128/8 bytes");
    memcpy(raw(), bytes.data(), sizeof(*this));
    timeHiAndVersion = ntohs(timeHiAndVersion);
    if (!check())
        throw TextException("malformed version 4 variant 1 UUID", Here());
}

bool
RandomUuid::check() const
{
    return (!EBIT_TEST(clockSeqHiAndReserved, 6) &&
            EBIT_TEST(clockSeqHiAndReserved, 7) &&
            !EBIT_TEST(timeHiAndVersion, 13) &&
            EBIT_TEST(timeHiAndVersion, 14) &&
            !EBIT_TEST(timeHiAndVersion, 15) &&
            !EBIT_TEST(timeHiAndVersion, 16));
}

RandomUuid::Serialized
RandomUuid::serialize() const
{
    auto serialized = serialize();
    auto *t = reinterpret_cast<uint16_t *>(&serialized[0] + offsetof(RandomUuid, timeHiAndVersion));
    *t = htons(*t);
    return serialized;
}

void
RandomUuid::print(std::ostream &os) const
{
    PrintHex(os << "UUID:", raw(), sizeof(*this));
}

bool
RandomUuid::operator ==(const RandomUuid &other) const
{
    return memcmp(raw(), other.raw(), sizeof(*this)) == 0;
}

