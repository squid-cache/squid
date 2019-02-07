/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BYTECOUNTER_H
#define SQUID_SRC_BYTECOUNTER_H

/// counter for accumulating byte values
class ByteCounter
{
public:
    ByteCounter() : bytes(0), kb(0) {}

    ByteCounter &operator +=(size_t v) {
        bytes += v;
        kb += (bytes >> 10);
        bytes &= 0x3FF;
        return *this;
    }

public:
    size_t bytes;
    size_t kb;
};

#endif /* SQUID_SRC_BYTECOUNTER_H */

