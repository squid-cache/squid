/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#include "squid.h"
#include "debug/Messages.h"
#include "event.h"
#include "fde.h"
#include "globals.h"
#include "md5.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "Store.h"
#include "store/Disk.h"
#include "store/SwapMetaIn.h"
#include "store_digest.h"
#include "store_key_md5.h"
#include "store_rebuild.h"
#include "StoreSearch.h"
#include "time/gadgets.h"

#include <cerrno>

static StoreRebuildData counts;

static void storeCleanup(void *);

// TODO: Either convert to Progress or replace with StoreRebuildData.
// TODO: Handle unknown totals (UFS cache_dir that lost swap.state) correctly.
typedef struct {
    /* total number of "swap.state" entries that will be read */
    int total;
    /* number of entries read so far */
    int scanned;
} store_rebuild_progress;

static store_rebuild_progress *RebuildProgress = nullptr;

void
StoreRebuildData::updateStartTime(const timeval &dirStartTime)
{
    startTime = started() ? std::min(startTime, dirStartTime) : dirStartTime;
}

static void
storeCleanup(void *)
{
    static int store_errors = 0;
    static StoreSearchPointer currentSearch;
    static int validated = 0;
    static int seen = 0;

    if (currentSearch == nullptr || currentSearch->isDone())
        currentSearch = Store::Root().search();

    size_t statCount = 500;

    // TODO: Avoid the loop (and ENTRY_VALIDATED) unless opt_store_doublecheck.
    while (statCount-- && !currentSearch->isDone() && currentSearch->next()) {
        StoreEntry *e;

        e = currentSearch->currentItem();

        ++seen;

        if (EBIT_TEST(e->flags, ENTRY_VALIDATED))
            continue;

        /*
         * Calling StoreEntry->release() has no effect because we're
         * still in 'store_rebuilding' state
         */
        if (!e->hasDisk())
            continue;

        if (opt_store_doublecheck)
            if (e->disk().doubleCheck(*e))
                ++store_errors;

        EBIT_SET(e->flags, ENTRY_VALIDATED);

        /*
         * Only set the file bit if we know its a valid entry
         * otherwise, set it in the validation procedure
         */

        if ((++validated & 0x3FFFF) == 0)
            /* TODO format the int with with a stream operator */
            debugs(20, DBG_IMPORTANT, "  " << validated << " Entries Validated so far.");
    }

    if (currentSearch->isDone()) {
        debugs(20, 2, "Seen: " << seen << " entries");
        debugs(20, Important(43), "Completed Validation Procedure" <<
               Debug::Extra << "Validated " << validated << " Entries" <<
               Debug::Extra << "store_swap_size = " << (Store::Root().currentSize()/1024.0) << " KB");
        --StoreController::store_dirs_rebuilding;
        assert(0 == StoreController::store_dirs_rebuilding);

        if (opt_store_doublecheck && store_errors) {
            fatalf("Quitting after finding %d cache index inconsistencies. " \
                   "Removing cache index will force its slow rebuild. " \
                   "Removing -S will let Squid start with an inconsistent " \
                   "cache index (at your own risk).\n", store_errors);
        }

        if (store_digest)
            storeDigestNoteStoreReady();

        currentSearch = nullptr;
    } else
        eventAdd("storeCleanup", storeCleanup, nullptr, 0.0, 1);
}

/* meta data recreated from disk image in swap directory */
void

storeRebuildComplete(StoreRebuildData *dc)
{
    if (dc) {
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
        counts.validations += dc->validations;
        counts.updateStartTime(dc->startTime);
    }
    // else the caller was not responsible for indexing its cache_dir

    assert(StoreController::store_dirs_rebuilding > 1);
    --StoreController::store_dirs_rebuilding;

    /*
     * When store_dirs_rebuilding == 1, it means we are done reading
     * or scanning all cache_dirs.  Now report the stats and start
     * the validation (storeCleanup()) thread.
     */

    if (StoreController::store_dirs_rebuilding > 1)
        return;

    const auto dt = tvSubDsec(counts.startTime, current_time);

    debugs(20, Important(46), "Finished rebuilding storage from disk." <<
           Debug::Extra << std::setw(7) << counts.scancount << " Entries scanned" <<
           Debug::Extra << std::setw(7) << counts.invalid << " Invalid entries" <<
           Debug::Extra << std::setw(7) << counts.badflags << " With invalid flags" <<
           Debug::Extra << std::setw(7) << counts.objcount << " Objects loaded" <<
           Debug::Extra << std::setw(7) << counts.expcount << " Objects expired" <<
           Debug::Extra << std::setw(7) << counts.cancelcount << " Objects canceled" <<
           Debug::Extra << std::setw(7) << counts.dupcount << " Duplicate URLs purged" <<
           Debug::Extra << std::setw(7) << counts.clashcount << " Swapfile clashes avoided" <<
           Debug::Extra << "Took " << std::setprecision(2) << dt << " seconds (" <<
           ((double) counts.objcount / (dt > 0.0 ? dt : 1.0)) << " objects/sec).");
    debugs(20, Important(56), "Beginning Validation Procedure");

    eventAdd("storeCleanup", storeCleanup, nullptr, 0.0, 1);

    xfree(RebuildProgress);

    RebuildProgress = nullptr;
}

/*
 * this is ugly.  We don't actually start any rebuild threads here,
 * but only initialize counters, etc.  The rebuild threads are
 * actually started by the filesystem "fooDirInit" function.
 */
void
storeRebuildStart(void)
{
    counts = StoreRebuildData(); // reset counters
    /*
     * Note: store_dirs_rebuilding is initialized to 1.
     *
     * When we parse the configuration and construct each swap dir,
     * the construction of that raises the rebuild count.
     *
     * This prevents us from trying to write clean logs until we
     * finished rebuilding - including after a reconfiguration that opens an
     * existing swapdir.  The corresponding decrement * occurs in
     * storeCleanup(), when it is finished.
     */
    RebuildProgress = (store_rebuild_progress *)xcalloc(Config.cacheSwap.n_configured,
                      sizeof(store_rebuild_progress));
}

/*
 * A fs-specific rebuild procedure periodically reports its
 * progress.
 */
void
storeRebuildProgress(int sd_index, int total, int sofar)
{
    static time_t last_report = 0;
    // TODO: Switch to int64_t and fix handling of unknown totals.
    double n = 0.0;
    double d = 0.0;

    if (sd_index < 0)
        return;

    if (sd_index >= Config.cacheSwap.n_configured)
        return;

    if (nullptr == RebuildProgress)
        return;

    RebuildProgress[sd_index].total = total;

    RebuildProgress[sd_index].scanned = sofar;

    if (squid_curtime - last_report < 15)
        return;

    for (sd_index = 0; sd_index < Config.cacheSwap.n_configured; ++sd_index) {
        n += (double) RebuildProgress[sd_index].scanned;
        d += (double) RebuildProgress[sd_index].total;
    }

    debugs(20, Important(57), "Indexing cache entries: " << Progress(n, d));
    last_report = squid_curtime;
}

void
Progress::print(std::ostream &os) const
{
    if (goal > 0) {
        const auto savedPrecision = os.precision(2);
        const auto percent = 100.0 * completed / goal;
        os << percent << "% (" << completed << " out of " << goal << ")";
        (void)os.precision(savedPrecision);
    } else if (!completed && !goal) {
        os << "nothing to do";
    } else {
        // unknown (i.e. negative) or buggy (i.e. zero when completed != 0) goal
        os << completed;
    }
}

bool
storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, StoreRebuildData &)
{
    if (fd < 0)
        return false;

    assert(buf.hasSpace()); // caller must allocate

    const int len = FD_READ_METHOD(fd, buf.space(), buf.spaceSize());
    ++ statCounter.syscalls.disk.reads;
    if (len < 0) {
        const int xerrno = errno;
        debugs(47, DBG_IMPORTANT, "WARNING: cache_dir[" << diskIndex << "]: " <<
               "Ignoring cached entry after meta data read failure: " << xstrerr(xerrno));
        return false;
    }

    buf.appended(len);
    return true;
}

bool
storeRebuildParseEntry(MemBuf &buf, StoreEntry &tmpe, cache_key *key,
                       StoreRebuildData &stats,
                       uint64_t expectedSize)
{
    uint64_t swap_hdr_len = 0;

    tmpe.key = nullptr;

    try {
        swap_hdr_len = Store::UnpackIndexSwapMeta(buf, tmpe, key);
    } catch (...) {
        debugs(47, Important(65), "WARNING: Indexer ignores a cache_dir entry: " << CurrentException);
        return false;
    }

    // TODO: consume parsed metadata?

    debugs(47,7, "successful swap meta unpacking; swap_file_sz=" << tmpe.swap_file_sz);

    if (!tmpe.key) {
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring keyless cache entry");
        return false;
    }

    /* check sizes */

    if (expectedSize > 0) {
        if (tmpe.swap_file_sz == 0) {
            tmpe.swap_file_sz = expectedSize;
        } else if (tmpe.swap_file_sz == (uint64_t)(expectedSize - swap_hdr_len)) {
            tmpe.swap_file_sz = expectedSize;
        } else if (tmpe.swap_file_sz != expectedSize) {
            debugs(47, DBG_IMPORTANT, "WARNING: Ignoring cache entry due to a " <<
                   "SIZE MISMATCH " << tmpe.swap_file_sz << "!=" << expectedSize);
            return false;
        }
    } else if (tmpe.swap_file_sz <= 0) {
        // if caller cannot handle unknown sizes, it must check after the call.
        debugs(47, 7, "unknown size: " << tmpe);
    }

    if (EBIT_TEST(tmpe.flags, KEY_PRIVATE)) {
        ++ stats.badflags;
        return false;
    }

    return true;
}

