/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "Debug.h"
#include "globals.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disk.h"
#include "store/Disks.h"
#include "swap_log_op.h"
#include "util.h" // for tvSubDsec() which should be in SquidTime.h

static STDIRSELECT storeDirSelectSwapDirRoundRobin;
static STDIRSELECT storeDirSelectSwapDirLeastLoad;
/**
 * This function pointer is set according to 'store_dir_select_algorithm'
 * in squid.conf.
 */
STDIRSELECT *storeDirSelectSwapDir = storeDirSelectSwapDirLeastLoad;

/// The entry size to use for Disk::canStore() size limit checks.
/// This is an optimization to avoid similar calculations in every cache_dir.
static int64_t
objectSizeForDirSelection(const StoreEntry &entry)
{
    // entry.objectLen() is negative here when we are still STORE_PENDING
    int64_t minSize = entry.mem_obj->expectedReplySize();

    // If entry size is unknown, use already accumulated bytes as an estimate.
    // Controller::accumulateMore() guarantees that there are enough of them.
    if (minSize < 0)
        minSize = entry.mem_obj->endOffset();

    assert(minSize >= 0);
    minSize += entry.mem_obj->swap_hdr_sz;
    return minSize;
}

/**
 * This new selection scheme simply does round-robin on all SwapDirs.
 * A SwapDir is skipped if it is over the max_size (100%) limit, or
 * overloaded.
 */
static int
storeDirSelectSwapDirRoundRobin(const StoreEntry * e)
{
    const int64_t objsize = objectSizeForDirSelection(*e);

    // Increment the first candidate once per selection (not once per
    // iteration) to reduce bias when some disk(s) attract more entries.
    static int firstCandidate = 0;
    if (++firstCandidate >= Config.cacheSwap.n_configured)
        firstCandidate = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        const int dirn = (firstCandidate + i) % Config.cacheSwap.n_configured;
        const SwapDir *sd = dynamic_cast<SwapDir*>(INDEXSD(dirn));

        int load = 0;
        if (!sd->canStore(*e, objsize, load))
            continue;

        if (load < 0 || load > 1000) {
            continue;
        }

        return dirn;
    }

    return -1;
}

/**
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
    int64_t best_objsize = -1;
    int least_load = INT_MAX;
    int load;
    int dirn = -1;
    int i;
    RefCount<SwapDir> SD;

    const int64_t objsize = objectSizeForDirSelection(*e);

    for (i = 0; i < Config.cacheSwap.n_configured; ++i) {
        SD = dynamic_cast<SwapDir *>(INDEXSD(i));
        SD->flags.selected = false;

        if (!SD->canStore(*e, objsize, load))
            continue;

        if (load < 0 || load > 1000)
            continue;

        if (load > least_load)
            continue;

        const int64_t cur_free = SD->maxSize() - SD->currentSize();

        /* If the load is equal, then look in more details */
        if (load == least_load) {
            /* best max-size fit */
            if (best_objsize != -1) {
                // cache_dir with the smallest max-size gets the known-size object
                // cache_dir with the largest max-size gets the unknown-size object
                if ((objsize != -1 && SD->maxObjectSize() > best_objsize) ||
                        (objsize == -1 && SD->maxObjectSize() < best_objsize))
                    continue;
            }

            /* most free */
            if (cur_free < most_free)
                continue;
        }

        least_load = load;
        best_objsize = SD->maxObjectSize();
        most_free = cur_free;
        dirn = i;
    }

    if (dirn >= 0)
        dynamic_cast<SwapDir *>(INDEXSD(dirn))->flags.selected = true;

    return dirn;
}

Store::Disks::Disks():
    largestMinimumObjectSize(-1),
    largestMaximumObjectSize(-1),
    secondLargestMaximumObjectSize(-1)
{
}

SwapDir *
Store::Disks::store(int const x) const
{
    return INDEXSD(x);
}

SwapDir &
Store::Disks::Dir(const int i)
{
    SwapDir *sd = INDEXSD(i);
    assert(sd);
    return *sd;
}

int
Store::Disks::callback()
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
Store::Disks::create()
{
    if (Config.cacheSwap.n_configured == 0) {
        debugs(0, DBG_PARSE_NOTE(DBG_CRITICAL), "No cache_dir stores are configured.");
    }

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (Dir(i).active())
            store(i)->create();
    }
}

StoreEntry *
Store::Disks::get(const cache_key *key)
{
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
                debugs(20, 7, "cache_dir " << idx << " has: " << *e);
                return e;
            }
        }
    }

    debugs(20, 6, "none of " << Config.cacheSwap.n_configured <<
           " cache_dirs have " << storeKeyText(key));
    return nullptr;
}

void
Store::Disks::init()
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
        if (Dir(i).active())
            store(i)->init();
    }

    if (strcasecmp(Config.store_dir_select_algorithm, "round-robin") == 0) {
        storeDirSelectSwapDir = storeDirSelectSwapDirRoundRobin;
        debugs(47, DBG_IMPORTANT, "Using Round Robin store dir selection");
    } else {
        storeDirSelectSwapDir = storeDirSelectSwapDirLeastLoad;
        debugs(47, DBG_IMPORTANT, "Using Least Load store dir selection");
    }
}

uint64_t
Store::Disks::maxSize() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (Dir(i).doReportStat())
            result += store(i)->maxSize();
    }

    return result;
}

uint64_t
Store::Disks::minSize() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (Dir(i).doReportStat())
            result += store(i)->minSize();
    }

    return result;
}

uint64_t
Store::Disks::currentSize() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (Dir(i).doReportStat())
            result += store(i)->currentSize();
    }

    return result;
}

uint64_t
Store::Disks::currentCount() const
{
    uint64_t result = 0;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (Dir(i).doReportStat())
            result += store(i)->currentCount();
    }

    return result;
}

int64_t
Store::Disks::maxObjectSize() const
{
    return largestMaximumObjectSize;
}

void
Store::Disks::updateLimits()
{
    largestMinimumObjectSize = -1;
    largestMaximumObjectSize = -1;
    secondLargestMaximumObjectSize = -1;

    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        const auto &disk = Dir(i);
        if (!disk.active())
            continue;

        if (disk.minObjectSize() > largestMinimumObjectSize)
            largestMinimumObjectSize = disk.minObjectSize();

        const auto diskMaxObjectSize = disk.maxObjectSize();
        if (diskMaxObjectSize > largestMaximumObjectSize) {
            if (largestMaximumObjectSize >= 0) // was set
                secondLargestMaximumObjectSize = largestMaximumObjectSize;
            largestMaximumObjectSize = diskMaxObjectSize;
        }
    }
}

int64_t
Store::Disks::accumulateMore(const StoreEntry &entry) const
{
    const auto accumulated = entry.mem_obj->availableForSwapOut();

    /*
     * Keep accumulating more bytes until the set of disks eligible to accept
     * the entry becomes stable, and, hence, accumulating more is not going to
     * affect the cache_dir selection. A stable set is usually reached
     * immediately (or soon) because most configurations either do not use
     * cache_dirs with explicit min-size/max-size limits or use the same
     * max-size limit for all cache_dirs (and low min-size limits).
     */

    // Can the set of min-size cache_dirs accepting this entry change?
    if (accumulated < largestMinimumObjectSize)
        return largestMinimumObjectSize - accumulated;

    // Can the set of max-size cache_dirs accepting this entry change
    // (other than when the entry exceeds the largest maximum; see below)?
    if (accumulated <= secondLargestMaximumObjectSize)
        return secondLargestMaximumObjectSize - accumulated + 1;

    /*
     * Checking largestMaximumObjectSize instead eliminates the risk of starting
     * to swap out an entry that later grows too big, but also implies huge
     * accumulation in most environments. Accumulating huge entries not only
     * consumes lots of RAM but also creates a burst of doPages() write requests
     * that overwhelm the disk. To avoid these problems, we take the risk and
     * allow swap out now. The disk will quit swapping out if the entry
     * eventually grows too big for its selected cache_dir.
     */
    debugs(20, 3, "no: " << accumulated << '>' <<
           secondLargestMaximumObjectSize << ',' << largestMinimumObjectSize);
    return 0;
}

void
Store::Disks::getStats(StoreInfoStats &stats) const
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
Store::Disks::stat(StoreEntry & output) const
{
    int i;

    /* Now go through each store, calling its stat routine */

    for (i = 0; i < Config.cacheSwap.n_configured; ++i) {
        storeAppendPrintf(&output, "\n");
        store(i)->stat(output);
    }
}

void
Store::Disks::reference(StoreEntry &e)
{
    e.disk().reference(e);
}

bool
Store::Disks::dereference(StoreEntry &e)
{
    return e.disk().dereference(e);
}

void
Store::Disks::updateHeaders(StoreEntry *e)
{
    Must(e);
    return e->disk().updateHeaders(e);
}

void
Store::Disks::maintain()
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
Store::Disks::sync()
{
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i)
        store(i)->sync();
}

void
Store::Disks::evictCached(StoreEntry &e) {
    if (e.hasDisk()) {
        // TODO: move into Fs::Ufs::UFSSwapDir::evictCached()
        if (!EBIT_TEST(e.flags, KEY_PRIVATE)) {
            // log before evictCached() below may clear hasDisk()
            storeDirSwapLog(&e, SWAP_LOG_DEL);
        }

        e.disk().evictCached(e);
        return;
    }

    if (const auto key = e.publicKey())
        evictIfFound(key);
}

void
Store::Disks::evictIfFound(const cache_key *key)
{
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        if (Dir(i).active())
            Dir(i).evictIfFound(key);
    }
}

bool
Store::Disks::anchorToCache(StoreEntry &entry, bool &inSync)
{
    if (const int cacheDirs = Config.cacheSwap.n_configured) {
        // ask each cache_dir until the entry is found; use static starting
        // point to avoid asking the same subset of disks more often
        // TODO: coordinate with put() to be able to guess the right disk often
        static int idx = 0;
        for (int n = 0; n < cacheDirs; ++n) {
            idx = (idx + 1) % cacheDirs;
            SwapDir &sd = Dir(idx);
            if (!sd.active())
                continue;

            if (sd.anchorToCache(entry, inSync)) {
                debugs(20, 3, "cache_dir " << idx << " anchors " << entry);
                return true;
            }
        }
    }

    debugs(20, 4, "none of " << Config.cacheSwap.n_configured <<
           " cache_dirs have " << entry);
    return false;
}

bool
Store::Disks::updateAnchored(StoreEntry &entry)
{
    return entry.hasDisk() &&
           Dir(entry.swap_dirn).updateAnchored(entry);
}

bool
Store::Disks::SmpAware()
{
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i) {
        // A mix is not supported, but we conservatively check every
        // dir because features like collapsed revalidation should
        // currently be disabled if any dir is SMP-aware
        if (Dir(i).smpAware())
            return true;
    }
    return false;
}

bool
Store::Disks::hasReadableEntry(const StoreEntry &e) const
{
    for (int i = 0; i < Config.cacheSwap.n_configured; ++i)
        if (Dir(i).active() && Dir(i).hasReadableEntry(e))
            return true;
    return false;
}

void
storeDirOpenSwapLogs()
{
    for (int dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn)
        INDEXSD(dirn)->openLog();
}

void
storeDirCloseSwapLogs()
{
    for (int dirn = 0; dirn < Config.cacheSwap.n_configured; ++dirn)
        INDEXSD(dirn)->closeLog();
}

/**
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

    // Check for store_dirs_rebuilding because fatal() often calls us in early
    // initialization phases, before store log is initialized and ready. Also,
    // some stores do not support log cleanup during Store rebuilding.
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

/* Globals that should be converted to static Store::Disks methods */

void
allocate_new_swapdir(Store::DiskConfig *swap)
{
    if (!swap->swapDirs) {
        swap->n_allocated = 4;
        swap->swapDirs = new SwapDir::Pointer[swap->n_allocated];
    }

    if (swap->n_allocated == swap->n_configured) {
        swap->n_allocated <<= 1;
        const auto tmp = new SwapDir::Pointer[swap->n_allocated];
        for (int i = 0; i < swap->n_configured; ++i) {
            tmp[i] = swap->swapDirs[i];
        }
        delete[] swap->swapDirs;
        swap->swapDirs = tmp;
    }
}

void
free_cachedir(Store::DiskConfig *swap)
{
    /* DON'T FREE THESE FOR RECONFIGURE */

    if (reconfiguring)
        return;

    /* TODO XXX this lets the swapdir free resources asynchronously
     * swap->swapDirs[i]->deactivate();
     * but there may be such a means already.
     * RBC 20041225
     */

    // only free's the array memory itself
    // the SwapDir objects may remain (ref-counted)
    delete[] swap->swapDirs;
    swap->swapDirs = nullptr;
    swap->n_allocated = 0;
    swap->n_configured = 0;
}

/* Globals that should be moved to some Store::UFS-specific logging module */

/**
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
    assert(e->hasDisk());
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

