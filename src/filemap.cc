/*
 * DEBUG: section 08    Swap File Bitmap
 * AUTHOR: Harvest Derived
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
#include "Debug.h"
#include "FileMap.h"

/* Number of bits in a long */
#if SIZEOF_LONG == 8
#define LONG_BIT_SHIFT 6
#define BITS_IN_A_LONG 0x40
#define LONG_BIT_MASK  0x3F
#define ALL_ONES (unsigned long) 0xFFFFFFFFFFFFFFFF
#elif SIZEOF_LONG == 4
#define LONG_BIT_SHIFT 5
#define BITS_IN_A_LONG 0x20
#define LONG_BIT_MASK  0x1F
#define ALL_ONES (unsigned long) 0xFFFFFFFF
#else
#define LONG_BIT_SHIFT 5
#define BITS_IN_A_LONG 0x20
#define LONG_BIT_MASK  0x1F
#define ALL_ONES (unsigned long) 0xFFFFFFFF
#endif

#define FM_INITIAL_NUMBER (1<<14)

FileMap::FileMap() :
        capacity_(FM_INITIAL_NUMBER), usedSlots_(0),
        nwords(capacity_ >> LONG_BIT_SHIFT)
{
    debugs(8, 3, HERE << "creating space for " << capacity_ << " files");
    debugs(8, 5, "--> " << nwords << " words of " << sizeof(*bitmap) << " bytes each");
    bitmap = (unsigned long *)xcalloc(nwords, sizeof(*bitmap));
}

void
FileMap::grow()
{
    int old_sz = nwords * sizeof(*bitmap);
    void *old_map = bitmap;
    capacity_ <<= 1;
    assert(capacity_ <= (1 << 24));	/* swap_filen is 25 bits, signed */
    nwords = capacity_ >> LONG_BIT_SHIFT;
    debugs(8, 3, HERE << " creating space for " << capacity_ << " files");
    debugs(8, 5, "--> " << nwords << " words of " << sizeof(*bitmap) << " bytes each");
    bitmap = (unsigned long *)xcalloc(nwords, sizeof(*bitmap));
    debugs(8, 3, "copying " << old_sz << " old bytes");
    memcpy(bitmap, old_map, old_sz);
    xfree(old_map);
    /* XXX account fm->bitmap */
}

bool
FileMap::setBit(sfileno file_number)
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));

    while (file_number >= capacity_)
        grow();

    bitmap[file_number >> LONG_BIT_SHIFT] |= bitmask;

    ++usedSlots_;

    return file_number;
}

/*
 * WARNING: clearBit does not perform array bounds
 * checking!  It assumes that 'file_number' is valid, and that the
 * bit is already set.  The caller must verify both of those
 * conditions by calling testBit
 * () first.
 */
void
FileMap::clearBit(sfileno file_number)
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));
    bitmap[file_number >> LONG_BIT_SHIFT] &= ~bitmask;
    --usedSlots_;
}

bool
FileMap::testBit(sfileno file_number) const
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));

    if (file_number >= capacity_)
        return 0;

    /* be sure the return value is an int, not a u_long */
    return (bitmap[file_number >> LONG_BIT_SHIFT] & bitmask ? 1 : 0);
}

sfileno
FileMap::allocate(sfileno suggestion)
{
    int word;

    if (suggestion >= capacity_)
        suggestion = 0;

    if (!testBit(suggestion))
        return suggestion;

    word = suggestion >> LONG_BIT_SHIFT;

    for (unsigned int count = 0; count < nwords; ++count) {
        if (bitmap[word] != ALL_ONES)
            break;

        word = (word + 1) % nwords;
    }

    for (unsigned char bit = 0; bit < BITS_IN_A_LONG; ++bit) {
        suggestion = ((unsigned long) word << LONG_BIT_SHIFT) | bit;

        if (!testBit(suggestion)) {
            return suggestion;
        }
    }

    grow();
    return allocate(capacity_ >> 1);
}

FileMap::~FileMap()
{
    safe_free(bitmap);
}
