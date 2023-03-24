/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREIOBUFFER_H
#define SQUID_STOREIOBUFFER_H

#include "base/Range.h"
#include "MemBuf.h"

class StoreIOBuffer
{

public:
    StoreIOBuffer(): flags{}, length(0), offset (0), data (nullptr) {}

    StoreIOBuffer(size_t aLength, int64_t anOffset, char *someData) :
        flags{},
        length (aLength), offset (anOffset), data (someData) {
    }

    /* Create a StoreIOBuffer from a MemBuf and offset */
    /* NOTE that MemBuf still "owns" the pointers, StoreIOBuffer is just borrowing them */
    StoreIOBuffer(MemBuf *aMemBuf, int64_t anOffset) :
        flags{},
        length(aMemBuf->contentSize()),
        offset (anOffset),
        data(aMemBuf->content()) {
    }

    StoreIOBuffer(MemBuf *aMemBuf, int64_t anOffset, size_t anLength) :
        flags{},
        length(anLength),
        offset (anOffset),
        data(aMemBuf->content()) {
    }

    Range<int64_t> range() const {
        return Range<int64_t>(offset, offset + length);
    }

    void dump() const {
        if (fwrite(data, length, 1, stderr)) {}
        if (fwrite("\n", 1, 1, stderr)) {}
    }

    struct {
        /// whether storeClientCopy() failed
        /// a true value essentially invalidates other flags and fields
        unsigned error:1;

        /// whether this storeClientCopy() answer delivered the last HTTP response body byte
        unsigned eof:1;
    } flags;
    size_t length;
    int64_t offset;
    char *data;
};

inline
std::ostream &
operator <<(std::ostream &os, const StoreIOBuffer &b)
{
    return os << "ioBuf(@" << b.offset << ", len=" << b.length << ", " <<
           (void*)b.data <<
           (b.flags.error ? ", ERR" : "") <<
           (b.flags.eof ? ", EOF" : "") <<
           ')';
}

#endif /* SQUID_STOREIOBUFFER_H */

