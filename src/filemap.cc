/* $Id: filemap.cc,v 1.7 1996/03/29 21:19:19 wessels Exp $ */

/* DEBUG: Section 8             filemap: swap file bitmap functions */

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

extern int storeGetSwapSpace _PARAMS((int));
extern void fatal_dump _PARAMS((char *));

static fileMap *fm = NULL;

fileMap *file_map_create(n)
     int n;			/* Number of files */
{
    fm = xcalloc(1, sizeof(fileMap));

    fm->max_n_files = n;
    fm->nwords = n >> LONG_BIT_SHIFT;
    debug(8, 1, "file_map_create: creating space for %d files\n", n);
    debug(8, 5, "--> %d words of %d bytes each\n",
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
	debug(8, 0, "file_map_bit_set: WARNING: file number %d is already set!\n",
	    file_number);
#endif

    fm->file_map[file_number >> LONG_BIT_SHIFT] |= bitmask;

    fm->n_files_in_map++;
    if (!fm->toggle && (fm->n_files_in_map > ((fm->max_n_files * 7) >> 3))) {
	fm->toggle++;
	debug(8, 0, "You should increment MAX_SWAP_FILE\n");
    } else if (fm->n_files_in_map > (fm->max_n_files - 100)) {
	debug(8, 0, "You've run out of swap file numbers. Freeing 1MB\n");
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

    debug(8, 0, "file_map_allocate: All %d files are in use!\n", fm->max_n_files);
    debug(8, 0, "You need to recompile with a larger value for MAX_SWAP_FILE\n");
    fatal_dump(NULL);
    return (0);			/* NOTREACHED */
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
