
/*
 * $Id: store_dir.cc,v 1.112 2000/06/25 22:28:43 wessels Exp $
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
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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

static int storeDirValidSwapDirSize(int, ssize_t);

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
 * Determine whether the given directory can handle this object
 * size
 *
 * Note: if the object size is -1, then the only swapdirs that
 * will return true here are ones that have max_obj_size = -1,
 * ie any-sized-object swapdirs. This is a good thing.
 */
static int
storeDirValidSwapDirSize(int swapdir, ssize_t objsize)
{
    /*
     * If the swapdir's max_obj_size is -1, then it definitely can
     */
    if (Config.cacheSwap.swapDirs[swapdir].max_objsize == -1)
	return 1;
    /*
     * Else, make sure that the max object size is larger than objsize
     */
    if (Config.cacheSwap.swapDirs[swapdir].max_objsize > objsize)
	return 1;
    else
	return 0;
}


#if UNUSED			/* Squid-2..4.DEVEL3 code */
/*
 * This new selection scheme simply does round-robin on all SwapDirs.
 * A SwapDir is skipped if it is over the max_size (100%) limit.  If
 * all SwapDir's are above the limit, then the first dirn that we
 * checked is returned.  Note that 'dirn' is guaranteed to advance even
 * if all SwapDirs are full.
 * 
 * XXX This function does NOT account for the read_only flag!
 */
static int
storeDirSelectSwapDir(void)
{
    static int dirn = 0;
    int i;
    SwapDir *sd;
    /*
     * yes, the '<=' is intentional.  If all dirs are full we want to
     * make sure 'dirn' advances every time this gets called, otherwise
     * we get stuck on one dir.
     */
    for (i = 0; i <= Config.cacheSwap.n_configured; i++) {
	if (++dirn >= Config.cacheSwap.n_configured)
	    dirn = 0;
	sd = &Config.cacheSwap.swapDirs[dirn];
	if (sd->cur_size > sd->max_size)
	    continue;
	return dirn;
    }
    return dirn;
}

#if USE_DISKD && EXPERIMENTAL
/*
 * This fileno selection function returns a fileno on the least
 * busy SwapDir.  Ties are broken by selecting the SwapDir with
 * the most free space.
 */
static int
storeDirSelectSwapDir(void)
{
    SwapDir *SD;
    int min_away = 10000;
    int min_size = 1 << 30;
    int dirn = 0;
    int i;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	if (SD->cur_size > SD->max_size)
	    continue;
	if (SD->u.diskd.away > min_away)
	    continue;
	if (SD->cur_size > min_size)
	    continue;
	if (SD->flags.read_only)
	    continue;
	min_away = SD->u.diskd.away;
	min_size = SD->cur_size;
	dirn = i;
    }
    return dirn;
}
#endif

#endif /* Squid-2.4.DEVEL3 code */

/*
 * Spread load across all of the store directories
 *
 * Note: We should modify this later on to prefer sticking objects
 * in the *tightest fit* swapdir to conserve space, along with the
 * actual swapdir usage. But for now, this hack will do while  
 * testing, so you should order your swapdirs in the config file
 * from smallest maxobjsize to unlimited (-1) maxobjsize.
 *
 * We also have to choose nleast == nconf since we need to consider
 * ALL swapdirs, regardless of state. Again, this is a hack while
 * we sort out the real usefulness of this algorithm.
 */
int
storeDirSelectSwapDir(const StoreEntry * e)
{
    ssize_t objsize;
    ssize_t least_size;
    ssize_t least_objsize;
    int least_load = 1000;
    int load;
    int dirn = -1;
    int i;
    SwapDir *SD;

    /* Calculate the object size */
    objsize = (ssize_t) objectLen(e);
    if (objsize != -1)
	objsize += e->mem_obj->swap_hdr_sz;
    /* Initial defaults */
    least_size = Config.cacheSwap.swapDirs[0].cur_size;
    least_objsize = Config.cacheSwap.swapDirs[0].max_objsize;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	SD->flags.selected = 0;
	if (SD->flags.read_only)
	    continue;
	/* Valid for object size check */
	if (!storeDirValidSwapDirSize(i, objsize))
	    continue;
	load = SD->checkobj(SD, e);
	if (load < 0)
	    continue;
	if (SD->cur_size > SD->max_size)
	    continue;
	if (load > least_load)
	    continue;
	if ((least_objsize > 0) && (objsize > least_objsize))
	    continue;
	/* Only use leastsize if the load is equal */
	if ((load == least_load) && (SD->cur_size > least_size))
	    continue;
	least_load = load;
	least_size = SD->cur_size;
	dirn = i;
    }

    if (dirn >= 0)
	Config.cacheSwap.swapDirs[dirn].flags.selected = 1;

    return dirn;
}



char *
storeSwapDir(int dirn)
{
    assert(0 <= dirn && dirn < Config.cacheSwap.n_configured);
    return Config.cacheSwap.swapDirs[dirn].path;
}

/*
 * An entry written to the swap log MUST have the following
 * properties.
 *   1.  It MUST be a public key.  It does no good to log
 *       a public ADD, change the key, then log a private
 *       DEL.  So we need to log a DEL before we change a
 *       key from public to private.
 *   2.  It MUST have a valid (> -1) swap_filen.
 */
void
storeDirSwapLog(const StoreEntry * e, int op)
{
    SwapDir *sd;
    assert(!EBIT_TEST(e->flags, KEY_PRIVATE));
    assert(e->swap_filen >= 0);
    /*
     * icons and such; don't write them to the swap log
     */
    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
	return;
    assert(op > SWAP_LOG_NOP && op < SWAP_LOG_MAX);
    debug(20, 3) ("storeDirSwapLog: %s %s %d %08X\n",
	swap_log_op_str[op],
	storeKeyText(e->key),
	e->swap_dirn,
	e->swap_filen);
    sd = &Config.cacheSwap.swapDirs[e->swap_dirn];
    sd->log.write(sd, e, op);
}

void
storeDirUpdateSwapSize(SwapDir * SD, size_t size, int sign)
{
    int k = ((size + 1023) >> 10) * sign;
    SD->cur_size += k;
    store_swap_size += k;
    if (sign > 0)
	n_disk_objects++;
    else if (sign < 0)
	n_disk_objects--;
}

void
storeDirStats(StoreEntry * sentry)
{
    int i;
    SwapDir *SD;

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

    /* Now go through each swapdir, calling its statfs routine */
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	storeAppendPrintf(sentry, "\n");
	SD = &(Config.cacheSwap.swapDirs[i]);
	storeAppendPrintf(sentry, "Store Directory #%d (%s): %s\n", i, SD->type,
	    storeSwapDir(i));
	SD->statfs(SD, sentry);
    }
}

void
storeDirConfigure(void)
{
    SwapDir *SD;
    int i;
    Config.Swap.maxSize = 0;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	Config.Swap.maxSize += SD->max_size;
	SD->low_size = (int) (((float) SD->max_size *
		(float) Config.Swap.lowWaterMark) / 100.0);
    }
}

void
storeDirDiskFull(sdirno dirn)
{
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
 *  This is a rewrite of the original function to troll each
 *  StoreDir and write the logs, and flush at the end of
 *  the run. Thanks goes to Eric Stern, since this solution
 *  came out of his COSS code.
 */
#define CLEAN_BUF_SZ 16384
int
storeDirWriteCleanLogs(int reopen)
{
    const StoreEntry *e = NULL;
    int n = 0;
    struct timeval start;
    double dt;
    SwapDir *sd;
    RemovalPolicyWalker **walkers;
    int dirn;
    int notdone = 1;
    if (store_dirs_rebuilding) {
	debug(20, 1) ("Not currently OK to rewrite swap log.\n");
	debug(20, 1) ("storeDirWriteCleanLogs: Operation aborted.\n");
	return 0;
    }
    debug(20, 1) ("storeDirWriteCleanLogs: Starting...\n");
    getCurrentTime();
    start = current_time;
    walkers = xcalloc(Config.cacheSwap.n_configured, sizeof *walkers);
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	sd = &Config.cacheSwap.swapDirs[dirn];
	if (sd->log.clean.start(sd) < 0) {
	    debug(20, 1) ("log.clean.start() failed for dir #%d\n", sd->index);
	    continue;
	}
    }
    while (notdone) {
	notdone = 0;
	for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	    sd = &Config.cacheSwap.swapDirs[dirn];
	    if (NULL == sd->log.clean.write)
		continue;
	    e = sd->log.clean.nextentry(sd);
	    if (!e)
		continue;
	    notdone = 1;
	    if (e->swap_filen < 0)
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
	    sd->log.clean.write(sd, e);
	    if ((++n & 0xFFFF) == 0) {
		getCurrentTime();
		debug(20, 1) ("  %7d entries written so far.\n", n);
	    }
	}
    }
    /* Flush */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	sd = &Config.cacheSwap.swapDirs[dirn];
	sd->log.clean.done(sd);
    }
    if (reopen)
	storeDirOpenSwapLogs();
    getCurrentTime();
    dt = tvSubDsec(start, current_time);
    debug(20, 1) ("  Finished.  Wrote %d entries.\n", n);
    debug(20, 1) ("  Took %3.1f seconds (%6.1f entries/sec).\n",
	dt, (double) n / (dt > 0.0 ? dt : 1.0));
    return n;
}
#undef CLEAN_BUF_SZ

/*
 * sync all avaliable fs'es ..
 */
void
storeDirSync(void)
{
    int i;
    SwapDir *SD;

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	SD = &Config.cacheSwap.swapDirs[i];
	if (SD->sync != NULL)
	    SD->sync(SD);
    }
}

/*
 * handle callbacks all avaliable fs'es ..
 */
void
storeDirCallback(void)
{
    int i, j;
    SwapDir *SD;
    static int ndir = 0;
    do {
	j = 0;
	for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	    if (ndir >= Config.cacheSwap.n_configured)
		ndir = ndir % Config.cacheSwap.n_configured;
	    SD = &Config.cacheSwap.swapDirs[ndir++];
	    if (NULL == SD->callback)
		continue;
	    j += SD->callback(SD);
	}
    } while (j > 0);
    ndir++;
}
