
/*
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
 * Copyright (c) 2003, Robert Collins  <robertc@squid-cache.org>
 */

#ifndef SQUID_STOREIOBUFFER_H
#define SQUID_STOREIOBUFFER_H

/* TODO: move this and the range() method into a .cci */
#include "Range.h"
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
