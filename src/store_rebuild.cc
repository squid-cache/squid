
/*
 * $Id: store_rebuild.cc,v 1.67 1999/12/30 17:36:58 wessels Exp $
 *
 * DEBUG: section 20    Store Rebuild Routines
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

static struct _store_rebuild_data counts;
static struct timeval rebuild_start;
static void storeCleanup(void *);

static int
storeCleanupDoubleCheck(const StoreEntry * e)
{
    /* XXX too UFS specific */
    struct stat sb;
    int dirn = e->swap_file_number >> SWAP_DIR_SHIFT;
    if (Config.cacheSwap.swapDirs[dirn].type == SWAPDIR_UFS)
	(void) 0;
    if (Config.cacheSwap.swapDirs[dirn].type == SWAPDIR_ASYNCUFS)
	(void) 0;
    else
	return 0;
    if (stat(storeUfsFullPath(e->swap_file_number, NULL), &sb) < 0) {
	debug(20, 0) ("storeCleanup: MISSING SWAP FILE\n");
	debug(20, 0) ("storeCleanup: FILENO %08X\n", e->swap_file_number);
	debug(20, 0) ("storeCleanup: PATH %s\n",
	    storeUfsFullPath(e->swap_file_number, NULL));
	storeEntryDump(e, 0);
	return -1;
    }
    if (e->swap_file_sz != sb.st_size) {
	debug(20, 0) ("storeCleanup: SIZE MISMATCH\n");
	debug(20, 0) ("storeCleanup: FILENO %08X\n", e->swap_file_number);
	debug(20, 0) ("storeCleanup: PATH %s\n",
	    storeUfsFullPath(e->swap_file_number, NULL));
	debug(20, 0) ("storeCleanup: ENTRY SIZE: %d, FILE SIZE: %d\n",
	    e->swap_file_sz, (int) sb.st_size);
	storeEntryDump(e, 0);
	return -1;
    }
    return 0;
}

static void
storeCleanup(void *datanotused)
{
    static int bucketnum = -1;
    static int validnum = 0;
    static int store_errors = 0;
    int validnum_start;
    StoreEntry *e;
    hash_link *link_ptr = NULL;
    hash_link *link_next = NULL;
    validnum_start = validnum;
    while (validnum - validnum_start < 50) {
	if (++bucketnum >= store_hash_buckets) {
	    debug(20, 1) ("  Completed Validation Procedure\n");
	    debug(20, 1) ("  Validated %d Entries\n", validnum);
	    debug(20, 1) ("  store_swap_size = %dk\n", store_swap_size);
	    store_dirs_rebuilding--;
	    assert(0 == store_dirs_rebuilding);
	    if (opt_store_doublecheck)
		assert(store_errors == 0);
	    if (store_digest)
		storeDigestNoteStoreReady();
	    return;
	}
	link_next = hash_get_bucket(store_table, bucketnum);
	while (NULL != (link_ptr = link_next)) {
	    link_next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;
	    if (EBIT_TEST(e->flags, ENTRY_VALIDATED))
		continue;
	    /*
	     * Calling storeRelease() has no effect because we're
	     * still in 'store_rebuilding' state
	     */
	    if (e->swap_file_number < 0)
		continue;
	    if (opt_store_doublecheck)
		if (storeCleanupDoubleCheck(e))
		    store_errors++;
	    EBIT_SET(e->flags, ENTRY_VALIDATED);
	    /*
	     * Only set the file bit if we know its a valid entry
	     * otherwise, set it in the validation procedure
	     */
	    storeDirUpdateSwapSize(e->swap_file_number, e->swap_file_sz, 1);
	    if ((++validnum & 0x3FFFF) == 0)
		debug(20, 1) ("  %7d Entries Validated so far.\n", validnum);
	}
    }
    eventAdd("storeCleanup", storeCleanup, NULL, 0.0, 1);
}

/* meta data recreated from disk image in swap directory */
void
storeRebuildComplete(struct _store_rebuild_data *dc)
{
    double dt;
    counts.objcount += dc->objcount;
    counts.expcount += dc->expcount;
    counts.scancount += dc->scancount;
    counts.clashcount += dc->clashcount;
    counts.dupcount += dc->dupcount;
    counts.cancelcount += dc->cancelcount;
    counts.invalid += dc->invalid;
    counts.badflags += dc->badflags;
    counts.bad_log_op += dc->bad_log_op;
    counts.zero_object_sz += dc->zero_object_sz;
    /*
     * When store_dirs_rebuilding == 1, it means we are done reading
     * or scanning all cache_dirs.  Now report the stats and start
     * the validation (storeCleanup()) thread.
     */
    if (store_dirs_rebuilding > 1)
	return;
    dt = tvSubDsec(rebuild_start, current_time);
    debug(20, 1) ("Finished rebuilding storage from disk.\n");
    debug(20, 1) ("  %7d Entries scanned\n", counts.scancount);
    debug(20, 1) ("  %7d Invalid entries.\n", counts.invalid);
    debug(20, 1) ("  %7d With invalid flags.\n", counts.badflags);
    debug(20, 1) ("  %7d Objects loaded.\n", counts.objcount);
    debug(20, 1) ("  %7d Objects expired.\n", counts.expcount);
    debug(20, 1) ("  %7d Objects cancelled.\n", counts.cancelcount);
    debug(20, 1) ("  %7d Duplicate URLs purged.\n", counts.dupcount);
    debug(20, 1) ("  %7d Swapfile clashes avoided.\n", counts.clashcount);
    debug(20, 1) ("  Took %3.1f seconds (%6.1f objects/sec).\n", dt,
	(double) counts.objcount / (dt > 0.0 ? dt : 1.0));
    debug(20, 1) ("Beginning Validation Procedure\n");
    eventAdd("storeCleanup", storeCleanup, NULL, 0.0, 1);
}

/*
 * this is ugly.  We don't actually start any rebuild threads here,
 * but only initialize counters, etc.  The rebuild threads are
 * actually started by the filesystem "fooDirInit" function.
 */
void
storeRebuildStart(void)
{
    memset(&counts, '\0', sizeof(counts));
    rebuild_start = current_time;
    /*
     * Note: store_dirs_rebuilding is initialized to 1 in globals.c.
     * This prevents us from trying to write clean logs until we
     * finished rebuilding for sure.  The corresponding decrement
     * occurs in storeCleanup(), when it is finished.
     */
}
