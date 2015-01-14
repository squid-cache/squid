/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "StoreSwapLogData.h"
#include "swap_log_op.h"

// Based on Internet Checksum (RFC 1071) algorithm but takes three 32bit ints.
// TODO: Consider Fletcher's checksum algorithm as a higher quality alternative
void
SwapChecksum24::set(uint32_t f1, uint32_t f2, uint32_t f3)
{
    uint64_t sum = f1;
    sum += f2;
    sum += f3;

    while (const uint64_t higherBits = sum >> 24)
        sum = (sum & 0xFFFFFF) + higherBits;

    sum = ~sum;

    raw[0] = static_cast<uint8_t>(sum);
    raw[1] = static_cast<uint8_t>(sum >> 8);
    raw[2] = static_cast<uint8_t>(sum >> 16);
}

/// Same as 3-argument SwapChecksum24::set() but for int32_t and uint64_t
void
SwapChecksum24::set(int32_t f1, uint64_t f2)
{
    // split the second 64bit word into two 32bit words
    set(static_cast<uint32_t>(f1),
        static_cast<uint32_t>(f2 >> 32),
        static_cast<uint32_t>(f2 & 0xFFFFFFFF));
}

std::ostream &
SwapChecksum24::print(std::ostream &os) const
{
    return os << raw[0] << '-' << raw[1] << '-' << raw[2];
}

StoreSwapLogData::StoreSwapLogData()
{
    memset(this, 0, sizeof(*this));
}

bool
StoreSwapLogData::sane() const
{
    SwapChecksum24 actualSum;
    actualSum.set(swap_filen, swap_file_sz);
    if (checksum != actualSum)
        return false;

    const time_t minTime = -2; // -1 is common; expires sometimes uses -2

    // Check what we safely can; for some fields any value might be valid
    return SWAP_LOG_NOP < op && op < SWAP_LOG_MAX &&
           swap_filen >= 0 &&
           timestamp >= minTime &&
           lastref >= minTime &&
           expires >= minTime &&
           lastmod >= minTime &&
           swap_file_sz > 0; // because swap headers ought to consume space
}

void
StoreSwapLogData::finalize()
{
    checksum.set(swap_filen, swap_file_sz);
}

StoreSwapLogHeader::StoreSwapLogHeader(): op(SWAP_LOG_VERSION), version(2),
    record_size(sizeof(StoreSwapLogData))
{
    checksum.set(version, record_size, 0);
}

bool
StoreSwapLogHeader::sane() const
{
    SwapChecksum24 actualSum;
    actualSum.set(version, record_size, 0);
    if (checksum != actualSum)
        return false;

    return op == SWAP_LOG_VERSION && version >= 2 && record_size > 0;
}

size_t
StoreSwapLogHeader::gapSize() const
{
    assert(record_size > 0);
    assert(static_cast<size_t>(record_size) > sizeof(*this));
    return static_cast<size_t>(record_size) - sizeof(*this);
}

