/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
    StoreIOBuffer():length(0), offset (0), data (NULL) {flags.error = 0;}

    StoreIOBuffer(size_t aLength, int64_t anOffset, char *someData) :
        length (aLength), offset (anOffset), data (someData) {
        flags.error = 0;
    }

    /* Create a StoreIOBuffer from a MemBuf and offset */
    /* NOTE that MemBuf still "owns" the pointers, StoreIOBuffer is just borrowing them */
    StoreIOBuffer(MemBuf *aMemBuf, int64_t anOffset) :
        length(aMemBuf->contentSize()),
        offset (anOffset),
        data(aMemBuf->content()) {
        flags.error = 0;
    }

    StoreIOBuffer(MemBuf *aMemBuf, int64_t anOffset, size_t anLength) :
        length(anLength),
        offset (anOffset),
        data(aMemBuf->content()) {
        flags.error = 0;
    }

    Range<int64_t> range() const {
        return Range<int64_t>(offset, offset + length);
    }

    void dump() const {
        if (fwrite(data, length, 1, stderr)) {}
        if (fwrite("\n", 1, 1, stderr)) {}
    }

    struct {
        unsigned error:1;
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
           (void*)b.data << (b.flags.error ? ", ERR" : "") << ')';
}

#endif /* SQUID_STOREIOBUFFER_H */

