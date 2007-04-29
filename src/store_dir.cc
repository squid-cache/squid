
/*
 * $Id: store_dir.cc,v 1.159 2007/04/28 22:26:38 hno Exp $
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
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
#include "Store.h"
#include "MemObject.h"
#include "SquidTime.h"
#include "SwapDir.h"

#if HAVE_STATVFS
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#endif /* HAVE_STATVFS */
/* statfs() needs <sys/param.h> and <sys/mount.h> on BSD systems */
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
/* Windows and Linux use sys/vfs.h */
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

#include "StoreHashIndex.h"

static STDIRSELECT storeDirSelectSwapDirRoundRobin;
static STDIRSELECT storeDirSelectSwapDirLeastLoad;

/*
 * store_dirs_rebuilding is initialized to _1_ as a hack so that
 * storeDirWriteCleanLogs() doesn't try to do anything unless _all_
 * cache_dirs have been read.  For example, without this hack, Squid
 * will try to write clean log files if -kparse fails (becasue it
 * calls fatal()).
 */
int StoreController::store_dirs_rebuilding = 1;

StoreController::StoreController() : swapDir (new StoreHashIndex())
{}

StoreController::~StoreController()
{}

/*
 * This function pointer is set according to 'store_dir_select_algorithm'
 * in squid.conf.
 */
STDIRSELECT *storeDirSelectSwapDir = storeDirSelectSwapDirLeastLoad;

void
StoreController::init()
{
    swapDir->init();

    if (0 == strcasecmp(Config.store_dir_select_algorithm, "round-robin")) {
        storeDirSelectSwapDir = storeDirSelectSwapDirRoundRobin;
        debugs(47, 1, "Using Round Robin store dir selection");
    } else {
        storeDirSelectSwapDir = storeDirSelectSwapDirLeastLoad;
        debugs(47, 1, "Using Least Load store dir selection");
    }
}

void
StoreController::createOneStore(Store &aStore)
{
    /*
     * On Windows, fork() is not available.
     * The following is a workaround for create store directories sequentially
     * when running on native Windows port.
     */
#ifndef _SQUID_MSWIN_

    if (fork())
        return;

#endif

    aStore.create();

#ifndef _SQUID_MSWIN_

    exit(0);

#endif
}

void
StoreController::create()
{
    swapDir->create();

#ifndef _SQUID_MSWIN_

    pid_t pid;

    do {
        int status;
#ifdef _SQUID_NEXT_

        pid = wait3(&status, WNOHANG, NULL);
#else

        pid = waitpid(-1, &status, 0);
#endif

    } while (pid > 0 || (pid < 0 && errno == EINTR));

#endif
}

/*
 * Determine whether the given directory can handle this object
 * size
 *
 * Note: if the object size is -1, then the only swapdirs that
 * will return true here are ones that have max_obj_size = -1,
 * ie any-sized-object swapdirs. This is a good thing.
 */
bool
SwapDir::objectSizeIsAcceptable(ssize_t objsize) const
{
    /*
     * If the swapdir's max_obj_size is -1, then it definitely can
     */

    if (max_objsize == -1)
        return true;

    /*
     * If the object size is -1, then if the storedir isn't -1 we
     * can't store it
     */
    if ((objsize == -1) && (max_objsize != -1))
        return false;

    /*
     * Else, make sure that the max object size is larger than objsize
     */
    return max_objsize > objsize;
}


/*
 * This new selection scheme simply does round-robin on all SwapDirs.
 * A SwapDir is skipped if it is over the max_size (100%) limit, or
 * overloaded.
 */
static int
storeDirSelectSwapDirRoundRobin(const StoreEntry * e)
{
    static int dirn = 0;
    int i;
    int load;
    RefCount<SwapDir> sd;

    for (i = 0; i <= Config.cacheSwap.n_configured; i++) {
        if (++dirn >= Config.cacheSwap.n_configured)
            dirn = 0;

        sd = dynamic_cast<SwapDir *>(INDEXSD(dirn));

        if (sd->flags.read_only)
            continue;

        if (sd->cur_size > sd->max_size)
            continue;

        if (!sd->objectSizeIsAcceptable(e->objectLen()))
            continue;

        /* check for error or overload condition */
        load = sd->canStore(*e);

        if (load < 0 || load > 1000) {
            continue;
        }

        return dirn;
    }

    return -1;
}

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
static int
storeDirSelectSwapDirLeastLoad(const StoreEntry * e)
{
    ssize_t objsize;
    ssize_t most_free = 0, cur_free;
    ssize_t least_objsize = -1;
    int least_load = INT_MAX;
    int load;
    int dirn = -1;
    int i;
    RefCount<SwapDir> SD;

    /* Calculate the object size */
    objsize = e->objectLen();

    if (objsize != -1)
        objsize += e->mem_obj->swap_hdr_sz;

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        SD = dynamic_cast<SwapDir *>(INDEXSD(i));
        SD->flags.selected = 0;
        load = SD->canStore(*e);

        if (load < 0 || load > 1000) {
            continue;
        }

        if (!SD->objectSizeIsAcceptable(objsize))
            continue;

        if (SD->flags.read_only)
            continue;

        if (SD->cur_size > SD->max_size)
            continue;

        if (load > least_load)
            continue;

        cur_free = SD->max_size - SD->cur_size;

        /* If the load is equal, then look in more details */
        if (load == least_load) {
            /* closest max_objsize fit */

            if (least_objsize != -1)
                if (SD->max_objsize > least_objsize || SD->max_objsize == -1)
                    continue;

            /* most free */
            if (cur_free < most_free)
                continue;
        }

        least_load = load;
        least_objsize = SD->max_objsize;
        most_free = cur_free;
        dirn = i;
    }

    if (dirn >= 0)
        dynamic_cast<SwapDir *>(INDEXSD(dirn))->flags.selected = 1;

    return dirn;
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
    assert (e);
    assert(!EBIT_TEST(e->flags, KEY_PRIVATE));
    assert(e->swap_filen >= 0);
    /*
     * icons and such; don't write them to the swap log
     */

    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
        return;

    assert(op > SWAP_LOG_NOP && op < SWAP_LOG_MAX);

    debugs(20, 3, "storeDirSwapLog: " << 
           swap_log_op_str[op] << " " <<  
           e->getMD5Text() << " " <<  
           e->swap_dirn << " " << 
           std::hex << std::uppercase << std::setfill('0') << std::setw(8) << e->swap_filen);

    dynamic_cast<SwapDir *>(INDEXSD(e->swap_dirn))->logEntry(*e, op);
}

void
StoreController::updateSize(size_t size, int sign)
{
    fatal("StoreController has no independent size\n");
}

void
SwapDir::updateSize(size_t size, int sign)
{
    int blks = (size + fs.blksize - 1) / fs.blksize;
    int k = (blks * fs.blksize >> 10) * sign;
    cur_size += k;
    store_swap_size += k;

    if (sign > 0)
        n_disk_objects++;
    else if (sign < 0)
        n_disk_objects--;
}

void
StoreController::stat(StoreEntry &output) const
{
    storeAppendPrintf(&output, "Store Directory Statistics:\n");
    storeAppendPrintf(&output, "Store Entries          : %lu\n",
                      (unsigned long int)StoreEntry::inUseCount());
    storeAppendPrintf(&output, "Maximum Swap Size      : %8ld KB\n",
                      (long int) maxSize());
    storeAppendPrintf(&output, "Current Store Swap Size: %8lu KB\n",
                      store_swap_size);
    storeAppendPrintf(&output, "Current Capacity       : %d%% used, %d%% free\n",
                      percent((int) store_swap_size, (int) maxSize()),
                      percent((int) (maxSize() - store_swap_size), (int) maxSize()));
    /* FIXME Here we should output memory statistics */

    /* now the swapDir */
    swapDir->stat(output);
}

/* if needed, this could be taught to cache the result */
size_t
StoreController::maxSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->maxSize();
}

size_t
StoreController::minSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->minSize();
}

void
SwapDir::diskFull()
{
    if (cur_size >= max_size)
        return;

    max_size = cur_size;

    debugs(20, 1, "WARNING: Shrinking cache_dir #" << index << " to " << cur_size << " KB");
}

void
storeDirOpenSwapLogs(void)
{
    for (int dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn)
        dynamic_cast<SwapDir *>(INDEXSD(dirn))->openLog();
}

void
storeDirCloseSwapLogs(void)
{
    for (int dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn)
        dynamic_cast<SwapDir *>(INDEXSD(dirn))->closeLog();
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
int
storeDirWriteCleanLogs(int reopen)
{
    const StoreEntry *e = NULL;
    int n = 0;

    struct timeval start;
    double dt;
    RefCount<SwapDir> sd;
    int dirn;
    int notdone = 1;

    if (StoreController::store_dirs_rebuilding) {
        debugs(20, 1, "Not currently OK to rewrite swap log.");
        debugs(20, 1, "storeDirWriteCleanLogs: Operation aborted.");
        return 0;
    }

    debugs(20, 1, "storeDirWriteCleanLogs: Starting...");
    getCurrentTime();
    start = current_time;

    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
        sd = dynamic_cast<SwapDir *>(INDEXSD(dirn));

        if (sd->writeCleanStart() < 0) {
            debugs(20, 1, "log.clean.start() failed for dir #" << sd->index);
            continue;
        }
    }

    /*
     * This may look inefficient as CPU wise it is more efficient to do this
     * sequentially, but I/O wise the parallellism helps as it allows more
     * hdd spindles to be active.
     */
    while (notdone) {
        notdone = 0;

        for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
            sd = dynamic_cast<SwapDir *>(INDEXSD(dirn));

            if (NULL == sd->cleanLog)
                continue;

            e = sd->cleanLog->nextEntry();

            if (!e)
                continue;

            notdone = 1;

            if (!sd->canLog(*e))
                continue;

            sd->cleanLog->write(*e);

            if ((++n & 0xFFFF) == 0) {
                getCurrentTime();
                debugs(20, 1, "  " << std::setw(7) << n  <<
                       " entries written so far.");
            }
        }
    }

    /* Flush */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++)
        dynamic_cast<SwapDir *>(INDEXSD(dirn))->writeCleanDone();

    if (reopen)
        storeDirOpenSwapLogs();

    getCurrentTime();

    dt = tvSubDsec(start, current_time);

    debugs(20, 1, "  Finished.  Wrote " << n << " entries.");
    debugs(20, 1, "  Took "<< std::setw(3)<< std::setprecision(2) << dt <<
           " seconds ("<< std::setw(6) << ((double) n / (dt > 0.0 ? dt : 1.0)) << " entries/sec).");


    return n;
}

StoreSearch *
StoreController::search(String const url, HttpRequest *request)
{
    /* cheat, for now you can't search the memory hot cache */
    return swapDir->search(url, request);
}

StorePointer
StoreHashIndex::store(int const x) const
{
    return INDEXSD(x);
}

void
StoreController::sync(void)
{
    /* sync mem cache? */
    swapDir->sync();
}

/*
 * handle callbacks all avaliable fs'es 
 */
int
StoreController::callback()
{
    /* This will likely double count. Thats ok. */
    PROF_start(storeDirCallback);

    /* mem cache callbacks ? */
    int result = swapDir->callback();

    PROF_stop(storeDirCallback);

    return result;
}

int
storeDirGetBlkSize(const char *path, int *blksize)
{
#if HAVE_STATVFS

    struct statvfs sfs;

    if (statvfs(path, &sfs)) {
        debugs(50, 1, "" << path << ": " << xstrerror());
        *blksize = 2048;
        return 1;
    }

    *blksize = (int) sfs.f_frsize;
#else

    struct statfs sfs;

    if (statfs(path, &sfs)) {
        debugs(50, 1, "" << path << ": " << xstrerror());
        *blksize = 2048;
        return 1;
    }

    *blksize = (int) sfs.f_bsize;
#endif
    /*
     * Sanity check; make sure we have a meaningful value.
     */

    if (*blksize < 512)
        *blksize = 2048;

    return 0;
}

#define fsbtoblk(num, fsbs, bs) \
    (((fsbs) != 0 && (fsbs) < (bs)) ? \
            (num) / ((bs) / (fsbs)) : (num) * ((fsbs) / (bs)))
int
storeDirGetUFSStats(const char *path, int *totl_kb, int *free_kb, int *totl_in, int *free_in)
{
#if HAVE_STATVFS

    struct statvfs sfs;

    if (statvfs(path, &sfs)) {
        debugs(50, 1, "" << path << ": " << xstrerror());
        return 1;
    }

    *totl_kb = (int) fsbtoblk(sfs.f_blocks, sfs.f_frsize, 1024);
    *free_kb = (int) fsbtoblk(sfs.f_bfree, sfs.f_frsize, 1024);
    *totl_in = (int) sfs.f_files;
    *free_in = (int) sfs.f_ffree;
#else

    struct statfs sfs;

    if (statfs(path, &sfs)) {
        debugs(50, 1, "" << path << ": " << xstrerror());
        return 1;
    }

    *totl_kb = (int) fsbtoblk(sfs.f_blocks, sfs.f_bsize, 1024);
    *free_kb = (int) fsbtoblk(sfs.f_bfree, sfs.f_bsize, 1024);
    *totl_in = (int) sfs.f_files;
    *free_in = (int) sfs.f_ffree;
#endif

    return 0;
}

void
allocate_new_swapdir(_SquidConfig::_cacheSwap * swap)
{
    if (swap->swapDirs == NULL) {
        swap->n_allocated = 4;
        swap->swapDirs = static_cast<StorePointer *>(xcalloc(swap->n_allocated, sizeof(StorePointer)));
    }

    if (swap->n_allocated == swap->n_configured) {
        StorePointer *tmp;
        swap->n_allocated <<= 1;
        tmp = static_cast<StorePointer *>(xcalloc(swap->n_allocated, sizeof(StorePointer)));
        xmemcpy(tmp, swap->swapDirs, swap->n_configured * sizeof(SwapDir *));
        xfree(swap->swapDirs);
        swap->swapDirs = tmp;
    }
}

void
free_cachedir(_SquidConfig::_cacheSwap * swap)
{
    int i;
    /* DON'T FREE THESE FOR RECONFIGURE */

    if (reconfiguring)
        return;

    for (i = 0; i < swap->n_configured; i++) {
        /* TODO XXX this lets the swapdir free resources asynchronously
        * swap->swapDirs[i]->deactivate();
        * but there may be such a means already. 
        * RBC 20041225
        */
        swap->swapDirs[i] = NULL;
    }

    safe_free(swap->swapDirs);
    swap->swapDirs = NULL;
    swap->n_allocated = 0;
    swap->n_configured = 0;
}

/* this should be a virtual method on StoreEntry,
 * i.e. e->referenced()
 * so that the entry can notify the creating Store
 */
void
StoreController::reference(StoreEntry &e)
{
    /* Notify the fs that we're referencing this object again */

    if (e.swap_dirn > -1)
        e.store()->reference(e);

    /* Notify the memory cache that we're referencing this object again */
    if (e.mem_obj) {
        if (mem_policy->Referenced)
            mem_policy->Referenced(mem_policy, &e, &e.mem_obj->repl);
    }
}

void
StoreController::dereference(StoreEntry & e)
{
    /* Notify the fs that we're not referencing this object any more */

    if (e.swap_filen > -1)
        e.store()->dereference(e);

    /* Notify the memory cache that we're not referencing this object any more */
    if (e.mem_obj) {
        if (mem_policy->Dereferenced)
            mem_policy->Dereferenced(mem_policy, &e, &e.mem_obj->repl);
    }
}

StoreEntry *

StoreController::get
    (const cache_key *key)
{

    return swapDir->get
           (key);
}

void

StoreController::get
    (String const key, STOREGETCLIENT callback, void *cbdata)
{
    fatal("not implemented");
}

StoreHashIndex::StoreHashIndex()
{
    assert (store_table == NULL);
}

StoreHashIndex::~StoreHashIndex()
{
    if (store_table) {
        hashFreeItems(store_table, destroyStoreEntry);
        hashFreeMemory(store_table);
        store_table = NULL;
    }
}

int
StoreHashIndex::callback()
{
    int result = 0;
    int j;
    static int ndir = 0;

    do {
        j = 0;

        for (int i = 0; i < Config.cacheSwap.n_configured; i++) {
            if (ndir >= Config.cacheSwap.n_configured)
                ndir = ndir % Config.cacheSwap.n_configured;

            int temp_result = store(ndir)->callback();

            ++ndir;

            j += temp_result;

            result += temp_result;

            if (j > 100)
                fatal ("too much io\n");
        }
    } while (j > 0);

    ndir++;

    return result;
}

void
StoreHashIndex::create()
{
    for (int i = 0; i < Config.cacheSwap.n_configured; i++)
        store(i)->create();
}

/* Lookup an object in the cache.
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *

StoreHashIndex::get
    (const cache_key *key)
{
    PROF_start(storeGet);
    debugs(20, 3, "storeGet: looking up " << storeKeyText(key));
    StoreEntry *p = static_cast<StoreEntry *>(hash_lookup(store_table, key));
    PROF_stop(storeGet);
    return p;
}

void

StoreHashIndex::get
    (String const key, STOREGETCLIENT callback, void *cbdata)
{
    fatal("not implemented");
}

void
StoreHashIndex::init()
{
    /* Calculate size of hash table (maximum currently 64k buckets).  */
    /* this is very bogus, its specific to the any Store maintaining an
     * in-core index, not global */
    size_t buckets = Store::Root().maxSize() / Config.Store.avgObjectSize;
    debugs(20, 1, "Swap maxSize " << Store::Root().maxSize() <<
           " KB, estimated " << buckets << " objects");
    buckets /= Config.Store.objectsPerBucket;
    debugs(20, 1, "Target number of buckets: " << buckets);
    /* ideally the full scan period should be configurable, for the
     * moment it remains at approximately 24 hours.  */
    store_hash_buckets = storeKeyHashBuckets(buckets);
    debugs(20, 1, "Using " << store_hash_buckets << " Store buckets");
    debugs(20, 1, "Max Mem  size: " << ( Config.memMaxSize >> 10) << " KB");
    debugs(20, 1, "Max Swap size: " << Store::Root().maxSize() << " KB");

    store_table = hash_create(storeKeyHashCmp,
                              store_hash_buckets, storeKeyHashHash);

    for (int i = 0; i < Config.cacheSwap.n_configured; i++)
        /* this starts a search of the store dirs, loading their
         * index. under the new Store api this should be
         * driven by the StoreHashIndex, not by each store.
        *
        * That is, the HashIndex should perform a search of each dir it is
        * indexing to do the hash insertions. The search is then able to 
        * decide 'from-memory', or 'from-clean-log' or 'from-dirty-log' or
        * 'from-no-log'.
        *
         * Step 1: make the store rebuilds use a search internally
        * Step 2: change the search logic to use the four modes described
        *         above
        * Step 3: have the hash index walk the searches itself.
         */
        store(i)->init();

}

size_t
StoreHashIndex::maxSize() const
{
    int i;
    size_t result = 0;

    for (i = 0; i < Config.cacheSwap.n_configured; i++)
        result += store(i)->maxSize();

    return result;
}

size_t
StoreHashIndex::minSize() const
{
    size_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; i++)
        result += store(i)->minSize();

    return result;
}

void
StoreHashIndex::stat(StoreEntry & output) const
{
    int i;

    /* Now go through each store, calling its stat routine */

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        storeAppendPrintf(&output, "\n");
        store(i)->stat(output);
    }
}

void
StoreHashIndex::reference(StoreEntry&)
{}

void
StoreHashIndex::dereference(StoreEntry&)
{}

void
StoreHashIndex::maintain()
{
    int i;
    /* walk each fs */

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        /* XXX FixMe: This should be done "in parallell" on the different
         * cache_dirs, not one at a time.
         */
        /* call the maintain function .. */
        store(i)->maintain();
    }
}

void
StoreHashIndex::updateSize(size_t, int)
{}

void
StoreHashIndex::sync()
{
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i)
        store(i)->sync();
}

StoreSearch *
StoreHashIndex::search(String const url, HttpRequest *)
{
    if (url.size())
        fatal ("Cannot search by url yet\n");

    return new StoreSearchHashIndex (this);
}

CBDATA_CLASS_INIT(StoreSearchHashIndex);

StoreSearchHashIndex::StoreSearchHashIndex(RefCount<StoreHashIndex> aSwapDir) : sd(aSwapDir), _done (false), bucket (0)
{}

/* do not link
StoreSearchHashIndex::StoreSearchHashIndex(StoreSearchHashIndex const &);
*/

StoreSearchHashIndex::~StoreSearchHashIndex()
{}

void
StoreSearchHashIndex::next(void (callback)(void *cbdata), void *cbdata)
{
    next();
    callback (cbdata);
}

bool
StoreSearchHashIndex::next()
{
    if (entries.size())
        entries.pop_back();

    while (!isDone() && !entries.size())
        copyBucket();

    return currentItem() != NULL;
}

bool
StoreSearchHashIndex::error() const
{
    return false;
}

bool
StoreSearchHashIndex::isDone() const
{
    return bucket >= store_hash_buckets || _done;
}

StoreEntry *
StoreSearchHashIndex::currentItem()
{
    if (!entries.size())
        return NULL;

    return entries.back();
}

void
StoreSearchHashIndex::copyBucket()
{
    /* probably need to lock the store entries...
     * we copy them all to prevent races on the links. */
    debugs(47, 3, "StoreSearchHashIndex::copyBucket #" << bucket);
    assert (!entries.size());
    hash_link *link_ptr = NULL;
    hash_link *link_next = NULL;
    link_next = hash_get_bucket(store_table, bucket);

    while (NULL != (link_ptr = link_next)) {
        link_next = link_ptr->next;
        StoreEntry *e = (StoreEntry *) link_ptr;

        entries.push_back(e);
    }

    bucket++;
    debugs(47,3, "got entries: " << entries.size());
}
