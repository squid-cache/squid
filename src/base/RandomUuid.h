/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_RANDOM_UUID_H
#define SQUID_SRC_BASE_RANDOM_UUID_H

#include <array>
#include <iosfwd>

/// 128-bit Universally Unique IDentifier (UUID), version 4 (variant 1) as
/// defined by RFC 4122. These UUIDs are generated from pseudo-random numbers.
class RandomUuid
{
public:
    using Serialized = std::array<char, 128/8>;

    /// creates a new unique ID (i.e. not a "nil UUID" in RFC 4122 terminology)
    RandomUuid();

    /// imports a UUID value that was exported using the serialize() API
    RandomUuid(const Serialized &);

    RandomUuid(RandomUuid &&) = default;
    RandomUuid &operator=(RandomUuid &&) = default;

    // (Implicit) copying is prohibited to prevent accidental duplication of
    // supposed-to-be-unique values. Use clone() when duplication is needed.
    RandomUuid(const RandomUuid &) = delete;
    RandomUuid &operator=(const RandomUuid &) = delete;

    /// exports UUID value; suitable for long-term storage
    Serialized serialize() const { return *reinterpret_cast<const Serialized *>(raw()); }

    bool operator ==(const RandomUuid &) const;
    bool operator !=(const RandomUuid &other) const { return !(*this == other); }

    /// creates a UUID object with the same value as this UUID
    RandomUuid clone() const { return RandomUuid(serialize()); }

    /// writes a human-readable representation
    void print(std::ostream &os) const;

private:
    /// read/write access to storage bytes
    char *raw() { return reinterpret_cast<char*>(this); }

    /// read-only access to storage bytes
    const char *raw() const { return reinterpret_cast<const char*>(this); }

    /*
     * These field sizes and names come from RFC 4122 Section 4.1.2. They do not
     * accurately represent the actual UUID version 4 structure which, the six
     * version/variant bits aside, contains just random bits.
     */
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqHiAndReserved;
    uint8_t clockSeqLow;
    uint8_t node[6];
};

#endif /* SQUID_SRC_BASE_RANDOM_UUID_H */

