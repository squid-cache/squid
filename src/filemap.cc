
/*
 * $Id$
 *
 * DEBUG: section 8     Swap File Bitmap
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

fileMap *
file_map_create(void)
{
    fileMap *fm = (fileMap *)xcalloc(1, sizeof(fileMap));
    fm->max_n_files = FM_INITIAL_NUMBER;
    fm->nwords = fm->max_n_files >> LONG_BIT_SHIFT;
    debugs(8, 3, "file_map_create: creating space for " << fm->max_n_files << " files");
    debugs(8, 5, "--> " << fm->nwords << " words of " << sizeof(*fm->file_map) << " bytes each");
    fm->file_map = (unsigned long *)xcalloc(fm->nwords, sizeof(*fm->file_map));
    /* XXX account fm->file_map */
    return fm;
}

static void
file_map_grow(fileMap * fm)
{
    int old_sz = fm->nwords * sizeof(*fm->file_map);
    void *old_map = fm->file_map;
    fm->max_n_files <<= 1;
    assert(fm->max_n_files <= (1 << 24));	/* swap_filen is 25 bits, signed */
    fm->nwords = fm->max_n_files >> LONG_BIT_SHIFT;
    debugs(8, 3, "file_map_grow: creating space for " << fm->max_n_files << " files");
    fm->file_map = (unsigned long *)xcalloc(fm->nwords, sizeof(*fm->file_map));
    debugs(8, 3, "copying " << old_sz << " old bytes");
    xmemcpy(fm->file_map, old_map, old_sz);
    xfree(old_map);
    /* XXX account fm->file_map */
}

int
file_map_bit_set(fileMap * fm, int file_number)
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));

    while (file_number >= fm->max_n_files)
        file_map_grow(fm);

    fm->file_map[file_number >> LONG_BIT_SHIFT] |= bitmask;

    fm->n_files_in_map++;

    return file_number;
}

/*
 * WARNING: file_map_bit_reset does not perform array bounds
 * checking!  It assumes that 'file_number' is valid, and that the
 * bit is already set.  The caller must verify both of those
 * conditions by calling file_map_bit_test() first.
 */
void
file_map_bit_reset(fileMap * fm, int file_number)
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));
    fm->file_map[file_number >> LONG_BIT_SHIFT] &= ~bitmask;
    fm->n_files_in_map--;
}

int
file_map_bit_test(fileMap * fm, int file_number)
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));

    if (file_number >= fm->max_n_files)
        return 0;

    /* be sure the return value is an int, not a u_long */
    return (fm->file_map[file_number >> LONG_BIT_SHIFT] & bitmask ? 1 : 0);
}

int
file_map_allocate(fileMap * fm, int suggestion)
{
    int word;
    int bit;
    int count;

    if (suggestion >= fm->max_n_files)
        suggestion = 0;

    if (!file_map_bit_test(fm, suggestion))
        return suggestion;

    word = suggestion >> LONG_BIT_SHIFT;

    for (count = 0; count < fm->nwords; count++) {
        if (fm->file_map[word] != ALL_ONES)
            break;

        word = (word + 1) % fm->nwords;
    }

    for (bit = 0; bit < BITS_IN_A_LONG; bit++) {
        suggestion = ((unsigned long) word << LONG_BIT_SHIFT) | bit;

        if (!file_map_bit_test(fm, suggestion)) {
            return suggestion;
        }
    }

    debugs(8, 3, "growing from file_map_allocate");
    file_map_grow(fm);
    return file_map_allocate(fm, fm->max_n_files >> 1);
}

void
filemapFreeMemory(fileMap * fm)
{
    safe_free(fm->file_map);
    safe_free(fm);
}

#ifdef TEST

#define TEST_SIZE 1<<16
main(argc, argv)
{
    int i;

    fm = file_map_create(TEST_SIZE);

    for (i = 0; i < TEST_SIZE; ++i) {
        file_map_bit_set(i);
        assert(file_map_bit_test(i));
        file_map_bit_reset(i);
    }
}

#endif
