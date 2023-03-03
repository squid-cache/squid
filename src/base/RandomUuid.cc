/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/IoManip.h"
#include "base/Random.h"
#include "base/RandomUuid.h"
#include "base/TextException.h"
#include "defines.h"

#include <iostream>

static_assert(sizeof(RandomUuid) == 128/8, "RandomUuid has RFC 4122-prescribed 128-bit size");

RandomUuid::RandomUuid()
{
    // Generate random bits for populating our UUID.
    static std::mt19937_64 rng(RandomSeed64()); // produces 64-bit sized values
    const auto rnd1 = rng();
    const auto rnd2 = rng();

    // No real r.n.g. is perfect, but we assume that std::mt19937_64 quality is
    // high enough to make any imperfections irrelevant to this specific code.

    // bullet 3 of RFC 4122 Section 4.4 algorithm but setting _all_ bits (KISS)
    static_assert(sizeof(rnd1) + sizeof(rnd2) == sizeof(*this), "random bits fill a UUID");
    memcpy(raw(), &rnd1, sizeof(rnd1));
    memcpy(raw() + sizeof(rnd1), &rnd2, sizeof(rnd2));

    // bullet 2 of RFC 4122 Section 4.4 algorithm
    EBIT_CLR(timeHiAndVersion, 12);
    EBIT_CLR(timeHiAndVersion, 13);
    EBIT_SET(timeHiAndVersion, 14);
    EBIT_CLR(timeHiAndVersion, 15);

    // bullet 1 of RFC 4122 Section 4.4 algorithm
    EBIT_CLR(clockSeqHiAndReserved, 6);
    EBIT_SET(clockSeqHiAndReserved, 7);

    assert(sane());
}

RandomUuid::RandomUuid(const Serialized &bytes)
{
    static_assert(sizeof(*this) == sizeof(Serialized), "RandomUuid is deserialized with 128/8 bytes");
    memcpy(raw(), bytes.data(), sizeof(*this));
    timeLow = ntohl(timeLow);
    timeMid = ntohs(timeMid);
    timeHiAndVersion = ntohs(timeHiAndVersion);
    if (!sane())
        throw TextException("malformed version 4 variant 1 UUID", Here());
}

/// whether this (being constructed) object follows UUID version 4 variant 1 format
bool
RandomUuid::sane() const
{
    return (!EBIT_TEST(clockSeqHiAndReserved, 6) &&
            EBIT_TEST(clockSeqHiAndReserved, 7) &&
            !EBIT_TEST(timeHiAndVersion, 12) &&
            !EBIT_TEST(timeHiAndVersion, 13) &&
            EBIT_TEST(timeHiAndVersion, 14) &&
            !EBIT_TEST(timeHiAndVersion, 15));
}

RandomUuid::Serialized
RandomUuid::serialize() const
{
    assert(sane());
    auto toNetwork = clone();
    // Convert all multi-byte fields to network byte order so that the recipient
    // will consider our ID sane() and print() the same text representation.
    toNetwork.timeLow = htonl(timeLow);
    toNetwork.timeMid = htons(timeMid);
    toNetwork.timeHiAndVersion = htons(timeHiAndVersion);
    return *reinterpret_cast<const Serialized *>(toNetwork.raw());
}

void
RandomUuid::print(std::ostream &os) const
{
    const auto savedFlags = os.flags();
    const auto savedFill = os.fill('0');

    os << std::hex;

    os <<
       std::setw(8) << timeLow  << '-' <<
       std::setw(4) << timeMid << '-' <<
       std::setw(4) << timeHiAndVersion << '-' <<
       std::setw(2) << +clockSeqHiAndReserved << std::setw(2) << +clockSeqLow << '-';

    for (size_t i = 0; i < sizeof(node); ++i)
        os << std::setw(2) << +node[i];

    os.fill(savedFill);
    os.flags(savedFlags);
}

bool
RandomUuid::operator ==(const RandomUuid &other) const
{
    return memcmp(raw(), other.raw(), sizeof(*this)) == 0;
}

std::ostream &
operator<<(std::ostream &os, const RandomUuid &uuid)
{
    uuid.print(os);
    return os;
}

