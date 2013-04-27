
/*
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
#include "globals.h"
#include "mem_node.h"
#include "MemObject.h"
#include "MemStore.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "Store.h"
#include "store_key_md5.h"
#include "StoreHashIndex.h"
#include "SwapDir.h"
#include "swap_log_op.h"
#include "tools.h"

#if HAVE_STATVFS
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#endif /* HAVE_STATVFS */
/* statfs() needs <sys/param.h> and <sys/mount.h> on BSD systems */
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
/* Windows and Linux use sys/vfs.h */
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif

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
        , memStore(NULL)
{}

StoreController::~StoreController()
{
    delete memStore;
}

/*
 * This function pointer is set according to 'store_dir_select_algorithm'
 * in squid.conf.
 */
STDIRSELECT *storeDirSelectSwapDir = storeDirSelectSwapDirLeastLoad;

void
StoreController::init()
{
    if (Config.memShared && IamWorkerProcess()) {
        memStore = new MemStore;
        memStore->init();
    }

    swapDir->init();

    if (0 == strcasecmp(Config.store_dir_select_algorithm, "round-robin")) {
        storeDirSelectSwapDir = storeDirSelectSwapDirRoundRobin;
        debugs(47, DBG_IMPORTANT, "Using Round Robin store dir selection");
    } else {
        storeDirSelectSwapDir = storeDirSelectSwapDirLeastLoad;
        debugs(47, DBG_IMPORTANT, "Using Least Load store dir selection");
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
#if !_SQUID_MSWIN_

    if (fork())
        return;

#endif

    aStore.create();

#if !_SQUID_MSWIN_

    exit(0);

#endif
}

void
StoreController::create()
{
    swapDir->create();

#if !_SQUID_MSWIN_

    pid_t pid;

    do {
        int status;
#if _SQUID_NEXT_

        pid = wait3(&status, WNOHANG, NULL);
#else

        pid = waitpid(-1, &status, 0);
#endif

    } while (pid > 0 || (pid < 0 && errno == EINTR));

#endif
}

/**
 * Determine whether the given directory can handle this object
 * size
 *
 * Note: if the object size is -1, then the only swapdirs that
 * will return true here are ones that have min and max unset,
 * ie any-sized-object swapdirs. This is a good thing.
 */
bool
SwapDir::objectSizeIsAcceptable(int64_t objsize) const
{
    // If the swapdir has no range limits, then it definitely can
    if (min_objsize <= 0 && max_objsize == -1)
        return true;

    /*
     * If the object size is -1 and the storedir has limits we
     * can't store it there.
     */
    if (objsize == -1)
        return false;

    // Else, make sure that the object size will fit.
    if (max_objsize == -1 && min_objsize <= objsize)
        return true;
    else
        return min_objsize <= objsize && max_objsize > objsize;
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

    // e->objectLen() is negative at this point when we are still STORE_PENDING
    ssize_t objsize = e->mem_obj->expectedReplySize();
    if (objsize != -1)
        objsize += e->mem_obj->swap_hdr_sz;

    for (i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (++dirn >= Config.cacheSwap.n_configured)
            dirn = 0;

        sd = dynamic_cast<SwapDir *>(INDEXSD(dirn));

        if (!sd->canStore(*e, objsize, load))
            continue;

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
 * from smallest max-size= to largest max-size=.
 *
 * We also have to choose nleast == nconf since we need to consider
 * ALL swapdirs, regardless of state. Again, this is a hack while
 * we sort out the real usefulness of this algorithm.
 */
static int
storeDirSelectSwapDirLeastLoad(const StoreEntry * e)
{
    int64_t most_free = 0;
    ssize_t least_objsize = -1;
    int least_load = INT_MAX;
    int load;
    int dirn = -1;
    int i;
    RefCount<SwapDir> SD;

    // e->objectLen() is negative at this point when we are still STORE_PENDING
    ssize_t objsize = e->mem_obj->expectedReplySize();

    if (objsize != -1)
        objsize += e->mem_obj->swap_hdr_sz;

    for (i = 0; i < Config.cacheSwap.n_configured; ++i) {
        SD = dynamic_cast<SwapDir *>(INDEXSD(i));
        SD->flags.selected = 0;

        if (!SD->canStore(*e, objsize, load))
            continue;

        if (load < 0 || load > 1000)
            continue;

        if (load > least_load)
            continue;

        const int64_t cur_free = SD->maxSize() - SD->currentSize();

        /* If the load is equal, then look in more details */
        if (load == least_load) {
            /* closest max-size fit */

            if (least_objsize != -1)
                if (SD->maxObjectSize() > least_objsize)
                    continue;

            /* most free */
            if (cur_free < most_free)
                continue;
        }

        least_load = load;
        least_objsize = SD->maxObjectSize();
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
StoreController::getStats(StoreInfoStats &stats) const
{
    if (memStore)
        memStore->getStats(stats);
    else {
        // move this code to a non-shared memory cache class when we have it
        stats.mem.shared = false;
        stats.mem.capacity = Config.memMaxSize;
        stats.mem.size = mem_node::StoreMemSize();
        stats.mem.count = hot_obj_count;
    }

    swapDir->getStats(stats);

    // low-level info not specific to memory or disk cache
    stats.store_entry_count = StoreEntry::inUseCount();
    stats.mem_object_count = MemObject::inUseCount();
}

void
StoreController::stat(StoreEntry &output) const
{
    storeAppendPrintf(&output, "Store Directory Statistics:\n");
    storeAppendPrintf(&output, "Store Entries          : %lu\n",
                      (unsigned long int)StoreEntry::inUseCount());
    storeAppendPrintf(&output, "Maximum Swap Size      : %" PRIu64 " KB\n",
                      maxSize() >> 10);
    storeAppendPrintf(&output, "Current Store Swap Size: %.2f KB\n",
                      currentSize() / 1024.0);
    storeAppendPrintf(&output, "Current Capacity       : %.2f%% used, %.2f%% free\n",
                      Math::doublePercent(currentSize(), maxSize()),
                      Math::doublePercent((maxSize() - currentSize()), maxSize()));

    if (memStore)
        memStore->stat(output);

    /* now the swapDir */
    swapDir->stat(output);
}

/* if needed, this could be taught to cache the result */
uint64_t
StoreController::maxSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->maxSize();
}

uint64_t
StoreController::minSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->minSize();
}

uint64_t
StoreController::currentSize() const
{
    return swapDir->currentSize();
}

uint64_t
StoreController::currentCount() const
{
    return swapDir->currentCount();
}

int64_t
StoreController::maxObjectSize() const
{
    return swapDir->maxObjectSize();
}

void
SwapDir::diskFull()
{
    if (currentSize() >= maxSize())
        return;

    max_size = currentSize();

    debugs(20, DBG_IMPORTANT, "WARNING: Shrinking cache_dir #" << index << " to " << currentSize() / 1024.0 << " KB");
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
        debugs(20, DBG_IMPORTANT, "Not currently OK to rewrite swap log.");
        debugs(20, DBG_IMPORTANT, "storeDirWriteCleanLogs: Operation aborted.");
        return 0;
    }

    debugs(20, DBG_IMPORTANT, "storeDirWriteCleanLogs: Starting...");
    getCurrentTime();
    start = current_time;

    for (dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn) {
        sd = dynamic_cast<SwapDir *>(INDEXSD(dirn));

        if (sd->writeCleanStart() < 0) {
            debugs(20, DBG_IMPORTANT, "log.clean.start() failed for dir #" << sd->index);
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

        for (dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn) {
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
                debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << n  <<
                       " entries written so far.");
            }
        }
    }

    /* Flush */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn)
        dynamic_cast<SwapDir *>(INDEXSD(dirn))->writeCleanDone();

    if (reopen)
        storeDirOpenSwapLogs();

    getCurrentTime();

    dt = tvSubDsec(start, current_time);

    debugs(20, DBG_IMPORTANT, "  Finished.  Wrote " << n << " entries.");
    debugs(20, DBG_IMPORTANT, "  Took "<< std::setw(3)<< std::setprecision(2) << dt <<
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

SwapDir &
StoreHashIndex::dir(const int i) const
{
    SwapDir *sd = dynamic_cast<SwapDir*>(INDEXSD(i));
    assert(sd);
    return *sd;
}

void
StoreController::sync(void)
{
    if (memStore)
        memStore->sync();
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
        debugs(50, DBG_IMPORTANT, "" << path << ": " << xstrerror());
        *blksize = 2048;
        return 1;
    }

    *blksize = (int) sfs.f_frsize;
#else

    struct statfs sfs;

    if (statfs(path, &sfs)) {
        debugs(50, DBG_IMPORTANT, "" << path << ": " << xstrerror());
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
        debugs(50, DBG_IMPORTANT, "" << path << ": " << xstrerror());
        return 1;
    }

    *totl_kb = (int) fsbtoblk(sfs.f_blocks, sfs.f_frsize, 1024);
    *free_kb = (int) fsbtoblk(sfs.f_bfree, sfs.f_frsize, 1024);
    *totl_in = (int) sfs.f_files;
    *free_in = (int) sfs.f_ffree;
#else

    struct statfs sfs;

    if (statfs(path, &sfs)) {
        debugs(50, DBG_IMPORTANT, "" << path << ": " << xstrerror());
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
allocate_new_swapdir(SquidConfig::_cacheSwap * swap)
{
    if (swap->swapDirs == NULL) {
        swap->n_allocated = 4;
        swap->swapDirs = static_cast<SwapDir::Pointer *>(xcalloc(swap->n_allocated, sizeof(SwapDir::Pointer)));
    }

    if (swap->n_allocated == swap->n_configured) {
        swap->n_allocated <<= 1;
        SwapDir::Pointer *const tmp = static_cast<SwapDir::Pointer *>(xcalloc(swap->n_allocated, sizeof(SwapDir::Pointer)));
        memcpy(tmp, swap->swapDirs, swap->n_configured * sizeof(SwapDir *));
        xfree(swap->swapDirs);
        swap->swapDirs = tmp;
    }
}

void
free_cachedir(SquidConfig::_cacheSwap * swap)
{
    int i;
    /* DON'T FREE THESE FOR RECONFIGURE */

    if (reconfiguring)
        return;

    for (i = 0; i < swap->n_configured; ++i) {
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
    // special entries do not belong to any specific Store, but are IN_MEMORY
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return;

    /* Notify the fs that we're referencing this object again */

    if (e.swap_dirn > -1)
        swapDir->reference(e);

    // Notify the memory cache that we're referencing this object again
    if (memStore && e.mem_status == IN_MEMORY)
        memStore->reference(e);

    // TODO: move this code to a non-shared memory cache class when we have it
    if (e.mem_obj) {
        if (mem_policy->Referenced)
            mem_policy->Referenced(mem_policy, &e, &e.mem_obj->repl);
    }
}

bool
StoreController::dereference(StoreEntry &e, bool wantsLocalMemory)
{
    // special entries do not belong to any specific Store, but are IN_MEMORY
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return true;

    bool keepInStoreTable = false; // keep only if somebody needs it there

    /* Notify the fs that we're not referencing this object any more */

    if (e.swap_filen > -1)
        keepInStoreTable = swapDir->dereference(e, wantsLocalMemory) || keepInStoreTable;

    // Notify the memory cache that we're not referencing this object any more
    if (memStore && e.mem_status == IN_MEMORY)
        keepInStoreTable = memStore->dereference(e, wantsLocalMemory) || keepInStoreTable;

    // TODO: move this code to a non-shared memory cache class when we have it
    if (e.mem_obj) {
        if (mem_policy->Dereferenced)
            mem_policy->Dereferenced(mem_policy, &e, &e.mem_obj->repl);
        // non-shared memory cache relies on store_table
        if (!memStore)
            keepInStoreTable = wantsLocalMemory || keepInStoreTable;
    }

    return keepInStoreTable;
}

StoreEntry *
StoreController::get(const cache_key *key)
{
    if (StoreEntry *e = swapDir->get(key)) {
        // TODO: ignore and maybe handleIdleEntry() unlocked intransit entries
        // because their backing store slot may be gone already.
        debugs(20, 3, HERE << "got in-transit entry: " << *e);
        return e;
    }

    if (memStore) {
        if (StoreEntry *e = memStore->get(key)) {
            debugs(20, 3, HERE << "got mem-cached entry: " << *e);
            return e;
        }
    }

    // TODO: this disk iteration is misplaced; move to StoreHashIndex when
    // the global store_table is no longer used for in-transit objects.
    if (const int cacheDirs = Config.cacheSwap.n_configured) {
        // ask each cache_dir until the entry is found; use static starting
        // point to avoid asking the same subset of disks more often
        // TODO: coordinate with put() to be able to guess the right disk often
        static int idx = 0;
        for (int n = 0; n < cacheDirs; ++n) {
            idx = (idx + 1) % cacheDirs;
            SwapDir *sd = dynamic_cast<SwapDir*>(INDEXSD(idx));
            if (!sd->active())
                continue;

            if (StoreEntry *e = sd->get(key)) {
                debugs(20, 3, HERE << "cache_dir " << idx <<
                       " got cached entry: " << *e);
                return e;
            }
        }
    }

    debugs(20, 4, HERE << "none of " << Config.cacheSwap.n_configured <<
           " cache_dirs have " << storeKeyText(key));
    return NULL;
}

void
StoreController::get(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    fatal("not implemented");
}

// move this into [non-shared] memory cache class when we have one
/// whether e should be kept in local RAM for possible future caching
bool
StoreController::keepForLocalMemoryCache(const StoreEntry &e) const
{
    if (!e.memoryCachable())
        return false;

    // does the current and expected size obey memory caching limits?
    assert(e.mem_obj);
    const int64_t loadedSize = e.mem_obj->endOffset();
    const int64_t expectedSize = e.mem_obj->expectedReplySize(); // may be < 0
    const int64_t ramSize = max(loadedSize, expectedSize);
    const int64_t ramLimit = min(
                                 static_cast<int64_t>(Config.memMaxSize),
                                 static_cast<int64_t>(Config.Store.maxInMemObjSize));
    return ramSize <= ramLimit;
}

void
StoreController::maybeTrimMemory(StoreEntry &e, const bool preserveSwappable)
{
    bool keepInLocalMemory = false;
    if (memStore)
        keepInLocalMemory = memStore->keepInLocalMemory(e);
    else
        keepInLocalMemory = keepForLocalMemoryCache(e);

    debugs(20, 7, HERE << "keepInLocalMemory: " << keepInLocalMemory);

    if (!keepInLocalMemory)
        e.trimMemory(preserveSwappable);
}

void
StoreController::handleIdleEntry(StoreEntry &e)
{
    bool keepInLocalMemory = false;

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL)) {
        // Icons (and cache digests?) should stay in store_table until we
        // have a dedicated storage for them (that would not purge them).
        // They are not managed [well] by any specific Store handled below.
        keepInLocalMemory = true;
    } else if (memStore) {
        memStore->considerKeeping(e);
        // leave keepInLocalMemory false; memStore maintains its own cache
    } else {
        keepInLocalMemory = keepForLocalMemoryCache(e) && // in good shape and
                            // the local memory cache is not overflowing
                            (mem_node::InUseCount() <= store_pages_max);
    }

    // An idle, unlocked entry that only belongs to a SwapDir which controls
    // its own index, should not stay in the global store_table.
    if (!dereference(e, keepInLocalMemory)) {
        debugs(20, 5, HERE << "destroying unlocked entry: " << &e << ' ' << e);
        destroyStoreEntry(static_cast<hash_link*>(&e));
        return;
    }

    debugs(20, 5, HERE << "keepInLocalMemory: " << keepInLocalMemory);

    // TODO: move this into [non-shared] memory cache class when we have one
    if (keepInLocalMemory) {
        e.setMemStatus(IN_MEMORY);
        e.mem_obj->unlinkRequest();
    } else {
        e.purgeMem(); // may free e
    }
}

StoreHashIndex::StoreHashIndex()
{
    if (store_table)
        abort();
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

        for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
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

    ++ndir;

    return result;
}

void
StoreHashIndex::create()
{
    if (Config.cacheSwap.n_configured == 0) {
        debugs(0, DBG_PARSE_NOTE(DBG_CRITICAL), "No cache_dir stores are configured.");
    }

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (dir(i).active())
            store(i)->create();
    }
}

/* Lookup an object in the cache.
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *
StoreHashIndex::get(const cache_key *key)
{
    PROF_start(storeGet);
    debugs(20, 3, "storeGet: looking up " << storeKeyText(key));
    StoreEntry *p = static_cast<StoreEntry *>(hash_lookup(store_table, key));
    PROF_stop(storeGet);
    return p;
}

void
StoreHashIndex::get(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    fatal("not implemented");
}

void
StoreHashIndex::init()
{
    if (Config.Store.objectsPerBucket <= 0)
        fatal("'store_objects_per_bucket' should be larger than 0.");

    if (Config.Store.avgObjectSize <= 0)
        fatal("'store_avg_object_size' should be larger than 0.");

    /* Calculate size of hash table (maximum currently 64k buckets).  */
    /* this is very bogus, its specific to the any Store maintaining an
     * in-core index, not global */
    size_t buckets = (Store::Root().maxSize() + Config.memMaxSize) / Config.Store.avgObjectSize;
    debugs(20, DBG_IMPORTANT, "Swap maxSize " << (Store::Root().maxSize() >> 10) <<
           " + " << ( Config.memMaxSize >> 10) << " KB, estimated " << buckets << " objects");
    buckets /= Config.Store.objectsPerBucket;
    debugs(20, DBG_IMPORTANT, "Target number of buckets: " << buckets);
    /* ideally the full scan period should be configurable, for the
     * moment it remains at approximately 24 hours.  */
    store_hash_buckets = storeKeyHashBuckets(buckets);
    debugs(20, DBG_IMPORTANT, "Using " << store_hash_buckets << " Store buckets");
    debugs(20, DBG_IMPORTANT, "Max Mem  size: " << ( Config.memMaxSize >> 10) << " KB" <<
           (Config.memShared ? " [shared]" : ""));
    debugs(20, DBG_IMPORTANT, "Max Swap size: " << (Store::Root().maxSize() >> 10) << " KB");

    store_table = hash_create(storeKeyHashCmp,
                              store_hash_buckets, storeKeyHashHash);

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
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
        if (dir(i).active())
            store(i)->init();
    }
}

uint64_t
StoreHashIndex::maxSize() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (dir(i).doReportStat())
            result += store(i)->maxSize();
    }

    return result;
}

uint64_t
StoreHashIndex::minSize() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (dir(i).doReportStat())
            result += store(i)->minSize();
    }

    return result;
}

uint64_t
StoreHashIndex::currentSize() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (dir(i).doReportStat())
            result += store(i)->currentSize();
    }

    return result;
}

uint64_t
StoreHashIndex::currentCount() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (dir(i).doReportStat())
            result += store(i)->currentCount();
    }

    return result;
}

int64_t
StoreHashIndex::maxObjectSize() const
{
    int64_t result = -1;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (dir(i).active() && store(i)->maxObjectSize() > result)
            result = store(i)->maxObjectSize();
    }

    return result;
}

void
StoreHashIndex::getStats(StoreInfoStats &stats) const
{
    // accumulate per-disk cache stats
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        StoreInfoStats dirStats;
        store(i)->getStats(dirStats);
        stats += dirStats;
    }

    // common to all disks
    stats.swap.open_disk_fd = store_open_disk_fd;

    // memory cache stats are collected in StoreController::getStats(), for now
}

void
StoreHashIndex::stat(StoreEntry & output) const
{
    int i;

    /* Now go through each store, calling its stat routine */

    for (i = 0; i < Config.cacheSwap.n_configured; ++i) {
        storeAppendPrintf(&output, "\n");
        store(i)->stat(output);
    }
}

void
StoreHashIndex::reference(StoreEntry &e)
{
    e.store()->reference(e);
}

bool
StoreHashIndex::dereference(StoreEntry &e, bool wantsLocalMemory)
{
    return e.store()->dereference(e, wantsLocalMemory);
}

void
StoreHashIndex::maintain()
{
    int i;
    /* walk each fs */

    for (i = 0; i < Config.cacheSwap.n_configured; ++i) {
        /* XXX FixMe: This should be done "in parallell" on the different
         * cache_dirs, not one at a time.
         */
        /* call the maintain function .. */
        store(i)->maintain();
    }
}

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
StoreSearchHashIndex::next(void (aCallback)(void *), void *aCallbackData)
{
    next();
    aCallback (aCallbackData);
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

    ++bucket;
    debugs(47,3, "got entries: " << entries.size());
}
