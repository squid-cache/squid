/*
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

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
