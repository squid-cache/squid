
/*
 * $Id: store_dir.cc,v 1.95 1999/05/25 22:05:56 wessels Exp $
 *
 * DEBUG: section 47    Store Directory Routines
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

const char *SwapDirType[] =
{
    "ufs",
    "!ERROR!"
};

void
storeDirInit(void)
{
    int i;
    SwapDir *sd;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	sd = &Config.cacheSwap.swapDirs[i];
	sd->init(sd);
    }
}

void
storeCreateSwapDirectories(void)
{
    int i;
    SwapDir *sd;
    pid_t pid;
    int status;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	if (fork())
	    continue;
	sd = &Config.cacheSwap.swapDirs[i];
	sd->newfs(sd);
	exit(0);
    }
    do {
#ifdef _SQUID_NEXT_
	pid = wait3(&status, WNOHANG, NULL);
#else
	pid = waitpid(-1, &status, 0);
#endif
    } while (pid > 0 || (pid < 0 && errno == EINTR));
}

/*
 *Spread load across least 3/4 of the store directories
 */
static int
storeDirSelectSwapDir(void)
{
    double least_used = 1.0;
    double high = (double) Config.Swap.highWaterMark / 100.0;
    double u;
    int dirn;
    int i, j;
    SwapDir *SD;
    static int nleast = 0;
    static int nconf = 0;
    static int *dirq = NULL;
    static double *diru = NULL;
    /*
     * Handle simplest case of a single swap directory immediately
     */
    if (Config.cacheSwap.n_configured == 1)
	return 0;
    /*
     * Initialise dirq on the first call or on change of number of dirs
     */
    if (nconf != Config.cacheSwap.n_configured) {
	nconf = Config.cacheSwap.n_configured;
	nleast = (nconf * 3) / 4;
	safe_free(dirq);
	dirq = (int *) xmalloc(sizeof(int) * nleast);
	safe_free(diru);
	diru = (double *) xmalloc(sizeof(double) * nconf);
	for (j = 0; j < nleast; j++)
	    dirq[j] = -1;
    }
    /*
     * Scan for a non-negative dirn in the dirq array and return that one
     */
    dirn = -1;
    for (j = 0; j < nleast; j++) {
	dirn = dirq[j];
	if (dirn < 0)
	    continue;
	dirq[j] = -1;
	break;
    }
    /*
     * If we found a valid dirn return it
     */
    if (dirn >= 0)
	return dirn;
    /*
     * Now for the real guts of the algorithm - building the dirq array
     */
    for (i = 0; i < nconf; i++) {
	diru[i] = 1.1;
	SD = &Config.cacheSwap.swapDirs[i];
	SD->flags.selected = 0;
	if (SD->flags.read_only)
	    continue;
	u = (double) SD->cur_size / SD->max_size;
	if (u > high)
	    continue;
	diru[i] = u;
    }
    for (j = 0; j < nleast; j++) {
	dirq[j] = -1;
	least_used = 1.0;
	dirn = -1;
	for (i = 0; i < nconf; i++) {
	    if (diru[i] < least_used) {
		least_used = diru[i];
		dirn = i;
	    }
	}
	if (dirn < 0)
	    break;
	dirq[j] = dirn;
	diru[dirn] = 1.1;
	/* set selected flag for debugging/cachemgr only */
	Config.cacheSwap.swapDirs[dirn].flags.selected = 1;
    }
    /*
     * Setup default return of 0 if no least found
     */
    if (dirq[0] < 0)
	dirq[0] = 0;
    dirn = dirq[0];
    dirq[0] = -1;
    return dirn;
}

int
storeDirValidFileno(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    if (dirn > Config.cacheSwap.n_configured)
	return 0;
    if (dirn < 0)
	return 0;
    if (filn < 0)
	return 0;
    if (filn > Config.cacheSwap.swapDirs[dirn].map->max_n_files)
	return 0;
    return 1;
}

int
storeDirMapBitTest(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    return file_map_bit_test(Config.cacheSwap.swapDirs[dirn].map, filn);
}

void
storeDirMapBitSet(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_set(Config.cacheSwap.swapDirs[dirn].map, filn);
}

void
storeDirMapBitReset(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    int filn = fn & SWAP_FILE_MASK;
    file_map_bit_reset(Config.cacheSwap.swapDirs[dirn].map, filn);
}

int
storeDirMapAllocate(void)
{
    int dirn = storeDirSelectSwapDir();
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    int filn = file_map_allocate(SD->map, SD->suggest);
    SD->suggest = filn + 1;
    return (dirn << SWAP_DIR_SHIFT) | (filn & SWAP_FILE_MASK);
}

char *
storeSwapDir(int dirn)
{
    assert(0 <= dirn && dirn < Config.cacheSwap.n_configured);
    return Config.cacheSwap.swapDirs[dirn].path;
}

int
storeDirNumber(int swap_file_number)
{
    return swap_file_number >> SWAP_DIR_SHIFT;
}

int
storeDirProperFileno(int dirn, int fn)
{
    return (dirn << SWAP_DIR_SHIFT) | (fn & SWAP_FILE_MASK);
}

/*
 * An entry written to the swap log MUST have the following
 * properties.
 *   1.  It MUST be a public key.  It does no good to log
 *       a public ADD, change the key, then log a private
 *       DEL.  So we need to log a DEL before we change a
 *       key from public to private.
 *   2.  It MUST have a valid (> -1) swap_file_number.
 */
void
storeDirSwapLog(const StoreEntry * e, int op)
{
    int dirn = e->swap_file_number >> SWAP_DIR_SHIFT;
    SwapDir *sd;
    assert(dirn < Config.cacheSwap.n_configured);
    assert(!EBIT_TEST(e->flags, KEY_PRIVATE));
    assert(e->swap_file_number >= 0);
    /*
     * icons and such; don't write them to the swap log
     */
    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
	return;
    assert(op > SWAP_LOG_NOP && op < SWAP_LOG_MAX);
    debug(20, 3) ("storeDirSwapLog: %s %s %08X\n",
	swap_log_op_str[op],
	storeKeyText(e->key),
	e->swap_file_number);
    sd = &Config.cacheSwap.swapDirs[dirn];
    sd->obj.log(sd, e, op);
}

void
storeDirUpdateSwapSize(int fn, size_t size, int sign)
{
    int dirn = (fn >> SWAP_DIR_SHIFT) % Config.cacheSwap.n_configured;
    int k = ((size + 1023) >> 10) * sign;
    Config.cacheSwap.swapDirs[dirn].cur_size += k;
    store_swap_size += k;
    if (sign > 0)
	n_disk_objects++;
    else if (sign < 0)
	n_disk_objects--;
}

void
storeDirStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Store Directory Statistics:\n");
    storeAppendPrintf(sentry, "Store Entries          : %d\n",
	memInUse(MEM_STOREENTRY));
    storeAppendPrintf(sentry, "Maximum Swap Size      : %8d KB\n",
	Config.Swap.maxSize);
    storeAppendPrintf(sentry, "Current Store Swap Size: %8d KB\n",
	store_swap_size);
    storeAppendPrintf(sentry, "Current Capacity       : %d%% used, %d%% free\n",
	percent((int) store_swap_size, (int) Config.Swap.maxSize),
	percent((int) (Config.Swap.maxSize - store_swap_size), (int) Config.Swap.maxSize));
    storeUfsDirStats(sentry);	/* XXX */
}

int
storeDirMapBitsInUse(void)
{
    int i;
    int n = 0;
    for (i = 0; i < Config.cacheSwap.n_configured; i++)
	n += Config.cacheSwap.swapDirs[i].map->n_files_in_map;
    return n;
}

void
storeDirConfigure(void)
{
    SwapDir *SD;
    int n;
    int i;
    fileMap *fm;
    Config.Swap.maxSize = 0;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];;
	Config.Swap.maxSize += SD->max_size;
	n = 2 * SD->max_size / Config.Store.avgObjectSize;
	if (NULL == SD->map) {
	    /* first time */
	    SD->map = file_map_create(n);
	} else if (n > SD->map->max_n_files) {
	    /* it grew, need to expand */
	    fm = file_map_create(n);
	    filemapCopy(SD->map, fm);
	    filemapFreeMemory(SD->map);
	    SD->map = fm;
	}
	/* else it shrunk, and we leave the old one in place */
    }
}

void
storeDirDiskFull(int fn)
{
    int dirn = fn >> SWAP_DIR_SHIFT;
    SwapDir *SD = &Config.cacheSwap.swapDirs[dirn];
    assert(0 <= dirn && dirn < Config.cacheSwap.n_configured);
    SD->max_size = SD->cur_size;
    debug(20, 1) ("WARNING: Shrinking cache_dir #%d to %d KB\n",
	dirn, SD->cur_size);
}

void
storeDirOpenSwapLogs(void)
{
    int dirn;
    SwapDir *sd;
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	sd = &Config.cacheSwap.swapDirs[dirn];
	sd->log.open(sd);
    }
}

void
storeDirCloseSwapLogs(void)
{
    int dirn;
    SwapDir *sd;
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	sd = &Config.cacheSwap.swapDirs[dirn];
	sd->log.close(sd);
    }
}

/*
 *  storeDirWriteCleanLogs
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
#define CLEAN_BUF_SZ 16384
int
storeDirWriteCleanLogs(int reopen)
{
    StoreEntry *e = NULL;
    int n = 0;
    time_t start, stop, r;
    SwapDir *sd;
    int dirn;
    int N = Config.cacheSwap.n_configured;
    dlink_node *m;
    if (store_dirs_rebuilding) {
	debug(20, 1) ("Not currently OK to rewrite swap log.\n");
	debug(20, 1) ("storeDirWriteCleanLogs: Operation aborted.\n");
	return 0;
    }
    debug(20, 1) ("storeDirWriteCleanLogs: Starting...\n");
    start = squid_curtime;
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	sd = &Config.cacheSwap.swapDirs[dirn];
	if (sd->log.clean.open(sd) < 0) {
	    debug(20, 1) ("log.clean.open() failed for dir #%d\n", sd->index);
	    continue;
	}
    }
    for (m = store_list.tail; m; m = m->prev) {
	e = m->data;
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAPOUT_DONE)
	    continue;
	if (e->swap_file_sz <= 0)
	    continue;
	if (EBIT_TEST(e->flags, RELEASE_REQUEST))
	    continue;
	if (EBIT_TEST(e->flags, KEY_PRIVATE))
	    continue;
	if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
	    continue;
	dirn = storeDirNumber(e->swap_file_number);
	sd = &Config.cacheSwap.swapDirs[dirn];
	if (NULL == sd->log.clean.write)
	    continue;
	sd->log.clean.write(e, sd);
	if ((++n & 0xFFFF) == 0) {
	    getCurrentTime();
	    debug(20, 1) ("  %7d entries written so far.\n", n);
	}
    }
    /* flush */
    for (dirn = 0; dirn < N; dirn++) {
	sd = &Config.cacheSwap.swapDirs[dirn];
	if (NULL == sd->log.clean.write)
	    continue;
	sd->log.clean.write(NULL, sd);
    }
    if (reopen)
	storeDirOpenSwapLogs();
    stop = squid_curtime;
    r = stop - start;
    debug(20, 1) ("  Finished.  Wrote %d entries.\n", n);
    debug(20, 1) ("  Took %d seconds (%6.1f entries/sec).\n",
	r > 0 ? (int) r : 0,
	(double) n / (r > 0 ? r : 1));
    return n;
}
#undef CLEAN_BUF_SZ
