/*
 * $Id: filemap.cc,v 1.23 1998/02/10 22:29:51 wessels Exp $
 *
 * DEBUG: section 8     Swap File Bitmap
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
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

fileMap *
file_map_create(int n)
{
    fileMap *fm = xcalloc(1, sizeof(fileMap));
    fm->max_n_files = n;
    fm->nwords = n >> LONG_BIT_SHIFT;
    debug(8, 3) ("file_map_create: creating space for %d files\n", n);
    debug(8, 5) ("--> %d words of %d bytes each\n",
	fm->nwords, sizeof(unsigned long));
    fm->file_map = xcalloc(fm->nwords, sizeof(unsigned long));
    meta_data.misc += fm->nwords * sizeof(unsigned long);
    return fm;
}

int
file_map_bit_set(fileMap * fm, int file_number)
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));
    fm->file_map[file_number >> LONG_BIT_SHIFT] |= bitmask;
    fm->n_files_in_map++;
    if (!fm->toggle && (fm->n_files_in_map > ((fm->max_n_files * 7) >> 3))) {
	fm->toggle++;
	debug(8, 0) ("You should increment MAX_SWAP_FILE\n");
    } else if (fm->n_files_in_map > (fm->max_n_files - 100)) {
	fatal("You've run out of swap file numbers.");
    }
    return (file_number);
}

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
    /* be sure the return value is an int, not a u_long */
    return (fm->file_map[file_number >> LONG_BIT_SHIFT] & bitmask ? 1 : 0);
}

int
file_map_allocate(fileMap * fm, int suggestion)
{
    int word;
    int bit;
    int count;
    if (suggestion > fm->max_n_files)
	suggestion = 0;
    if (!file_map_bit_test(fm, suggestion)) {
	return file_map_bit_set(fm, suggestion);
    }
    word = suggestion >> LONG_BIT_SHIFT;
    for (count = 0; count < fm->nwords; count++) {
	if (fm->file_map[word] != ALL_ONES)
	    break;
	word = (word + 1) % fm->nwords;
    }
    for (bit = 0; bit < BITS_IN_A_LONG; bit++) {
	suggestion = ((unsigned long) word << LONG_BIT_SHIFT) | bit;
	if (!file_map_bit_test(fm, suggestion)) {
	    return file_map_bit_set(fm, suggestion);
	}
    }
    fatal("file_map_allocate: Exceeded filemap limit");
    return 0;			/* NOTREACHED */
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
