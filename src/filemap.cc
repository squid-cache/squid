static char rcsid[] = "filemap.c,v 1.5.6.3 1995/12/10 23:02:47 duane Exp";
/* 
 *  File:         main.c
 *  Description:  main loop for cache
 *  Author:       John Noll, USC
 *  Created:      Mon Dec 13 10:10:28 1993 (John Noll, USC) sfdif
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
/*
 * Maintain a bitmap of the allocated file numbers.  This
 * eliminates the call to stat() to find available file numbers
 *
 * We use a bitmap where the bit position corresponds to file number.
 * On create, we allocate the bit map, and then test, set, and reset it
 * in a handful of 1-liners.
 */
#include "config.h"
#include <stdlib.h>

#include "ansihelp.h"
#include "filemap.h"
#include "util.h"
#include "debug.h"

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

extern int storeGetSwapSpace _PARAMS((int));
extern void fatal_dump _PARAMS((char *));

static fileMap *fm = NULL;

fileMap *file_map_create(n)
     int n;			/* Number of files */
{
    fm = xcalloc(1, sizeof(fileMap));

    fm->max_n_files = n;
    fm->nwords = n >> LONG_BIT_SHIFT;
    debug(1, "file_map_create: creating space for %d files\n", n);
    debug(5, "--> %d words of %d bytes each\n",
	fm->nwords, sizeof(unsigned long));
    fm->file_map = (unsigned long *) xcalloc(fm->nwords, sizeof(unsigned long));
    return (fm);
}

int file_map_bit_set(file_number)
     int file_number;
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));

#ifdef XTRA_DEBUG
    if (fm->file_map[file_number >> LONG_BIT_SHIFT] & bitmask)
	debug(0, "file_map_bit_set: WARNING: file number %d is already set!\n",
	    file_number);
#endif

    fm->file_map[file_number >> LONG_BIT_SHIFT] |= bitmask;

    fm->n_files_in_map++;
    if (!fm->toggle && (fm->n_files_in_map > ((fm->max_n_files * 7) >> 3))) {
	fm->toggle++;
	debug(0, "You should increment MAX_SWAP_FILE\n");
    } else if (fm->n_files_in_map > (fm->max_n_files - 100)) {
	debug(0, "You've run out of swap file numbers. Freeing 1MB\n");
	storeGetSwapSpace(1000000);
    }
    return (file_number);
}

void file_map_bit_reset(file_number)
     int file_number;
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));

    fm->file_map[file_number >> LONG_BIT_SHIFT] &= ~bitmask;
    fm->n_files_in_map--;
}

int file_map_bit_test(file_number)
     int file_number;
{
    unsigned long bitmask = (1L << (file_number & LONG_BIT_MASK));
    /* be sure the return value is an int, not a u_long */
    return (fm->file_map[file_number >> LONG_BIT_SHIFT] & bitmask ? 1 : 0);
}

int file_map_allocate(suggestion)
     int suggestion;
{
    int word;
    int bit;
    int count;

    if (!file_map_bit_test(suggestion)) {
	fm->last_file_number_allocated = suggestion;
	return file_map_bit_set(suggestion);
    }
    word = suggestion >> LONG_BIT_SHIFT;
    for (count = 0; count < fm->nwords; count++) {
	if (fm->file_map[word] != ALL_ONES)
	    break;
	word = (word + 1) % fm->nwords;
    }

    for (bit = 0; bit < BITS_IN_A_LONG; bit++) {
	suggestion = ((unsigned long) word << LONG_BIT_SHIFT) | bit;
	if (!file_map_bit_test(suggestion)) {
	    fm->last_file_number_allocated = suggestion;
	    return file_map_bit_set(suggestion);
	}
    }

    debug(0, "file_map_allocate: All %d files are in use!\n", fm->max_n_files);
    debug(0, "You need to recompile with a larger value for MAX_SWAP_FILE\n");
    fatal_dump(NULL);
    /* NOTREACHED */
}

#ifdef TEST

#define TEST_SIZE 1<<16
main(argc, argv)
{
    int i;

    fm = file_map_create(TEST_SIZE);

    for (i = 0; i < TEST_SIZE; ++i) {
	file_map_bit_set(i);
	if (!file_map_bit_test(i))
	    fatal_dump(NULL);
	file_map_bit_reset(i);
    }
}
#endif
