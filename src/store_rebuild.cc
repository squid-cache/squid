/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "DebugMessages.h"
#include "event.h"
#include "globals.h"
#include "ipc/StrandCoord.h"
#include "md5.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "store/Disks.h"
#include "store_key_md5.h"
#include "store_rebuild.h"
#include "StoreSearch.h"
#include "tools.h"
// for tvSubDsec() which should be in SquidTime.h
#include "util.h"

#include <cerrno>
#include <vector>

static StoreRebuildData counts;

static void storeCleanup(void *);
static void StoreRebuildFinalize();

// TODO: Either convert to Progress or replace with StoreRebuildData.
// TODO: Handle unknown totals (UFS cache_dir that lost swap.state) correctly.
typedef struct {
    /* total number of "swap.state" entries that will be read */
    int total = 0;
    /* number of entries read so far */
    int scanned = 0;
} store_rebuild_progress;

typedef std::vector<store_rebuild_progress> RebuildProgressStats;
static RebuildProgressStats *RebuildProgress = nullptr;

void
StoreRebuildData::updateStartTime(const timeval &dirStartTime)
{
    startTime = started() ? std::min(startTime, dirStartTime) : dirStartTime;
}

static void
storeCleanup(void *)
{
    Store::Root().validate();
}

void
Store::Controller::validate()
{
    static int store_errors = 0;
    static StoreSearchPointer currentSearch;
    static int validated = 0;
    static int seen = 0;

    if (currentSearch == NULL || currentSearch->isDone())
        currentSearch = search();

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
               Debug::Extra << "store_swap_size = " << (currentSize()/1024.0) << " KB");

        if (opt_store_doublecheck && store_errors) {
            fatalf("Quitting after finding %d cache index inconsistencies. " \
                   "Removing cache index will force its slow rebuild. " \
                   "Removing -S will let Squid start with an inconsistent " \
                   "cache index (at your own risk).\n", store_errors);
        }

        currentSearch = NULL;
        markValidated();
        RunRegisteredHere(RegisteredRunner::useFullyIndexedStore);
    } else
        eventAdd("storeCleanup", storeCleanup, NULL, 0.0, 1);
}

// TODO: Convert to Store::Disk::noteRebuildCompleted(). Check other Disk-specific functions here.
/* meta data recreated from disk image in swap directory */
void
storeRebuildComplete(StoreRebuildData *dc, SwapDir &dir)
{
    dir.indexed = true;

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

    if (Store::Disks::AllIndexed())
        StoreRebuildFinalize();
}

static void
StoreRebuildPrint()
{
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
}

static void
StoreRebuildFinalize()
{
    assert(Store::Disks::AllIndexed());

    /*
     * We are done reading or scanning all cache_dirs. Now report the stats and start
     * the validation (storeCleanup()) thread.
     */

    // avoid printing misleading zero counters in kids that do not index cache_dirs
    if (counts.scancount)
        StoreRebuildPrint();

    delete RebuildProgress;
    RebuildProgress = nullptr;

    debugs(20, Important(56), "Beginning Validation Procedure");
    eventAdd("storeCleanup", storeCleanup, nullptr, 0.0, 1);
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
    if (Store::Disks::AllIndexed())
        StoreRebuildFinalize();
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

    if (!RebuildProgress)
        RebuildProgress = new RebuildProgressStats(Config.cacheSwap.n_configured);

    RebuildProgress->at(sd_index).total = total;

    RebuildProgress->at(sd_index).scanned = sofar;

    if (squid_curtime - last_report < 15)
        return;

    for (sd_index = 0; sd_index < Config.cacheSwap.n_configured; ++sd_index) {
        n += static_cast<double>(RebuildProgress->at(sd_index).scanned);
        d += static_cast<double>(RebuildProgress->at(sd_index).total);
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

#include "fde.h"
#include "Generic.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"

struct InitStoreEntry : public unary_function<StoreMeta, void> {
    InitStoreEntry(StoreEntry *anEntry, cache_key *aKey):what(anEntry),index(aKey) {}

    void operator()(StoreMeta const &x) {
        switch (x.getType()) {

        case STORE_META_KEY:
            assert(x.length == SQUID_MD5_DIGEST_LENGTH);
            memcpy(index, x.value, SQUID_MD5_DIGEST_LENGTH);
            break;

        case STORE_META_STD:
            struct old_metahdr {
                time_t timestamp;
                time_t lastref;
                time_t expires;
                time_t lastmod;
                size_t swap_file_sz;
                uint16_t refcount;
                uint16_t flags;
            } *tmp;
            tmp = (struct old_metahdr *)x.value;
            assert(x.length == STORE_HDR_METASIZE_OLD);
            what->timestamp = tmp->timestamp;
            what->lastref = tmp->lastref;
            what->expires = tmp->expires;
            what->lastModified(tmp->lastmod);
            what->swap_file_sz = tmp->swap_file_sz;
            what->refcount = tmp->refcount;
            what->flags = tmp->flags;
            break;

        case STORE_META_STD_LFS:
            assert(x.length == STORE_HDR_METASIZE);
            memcpy(&what->timestamp, x.value, STORE_HDR_METASIZE);
            break;

        default:
            break;
        }
    }

    StoreEntry *what;
    cache_key *index;
};

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
    int swap_hdr_len = 0;
    StoreMetaUnpacker aBuilder(buf.content(), buf.contentSize(), &swap_hdr_len);
    if (aBuilder.isBufferZero()) {
        debugs(47,5, HERE << "skipping empty record.");
        return false;
    }

    StoreMeta *tlv_list = nullptr;
    try {
        tlv_list = aBuilder.createStoreMeta();
    } catch (const std::exception &e) {
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring store entry because " << e.what());
        return false;
    }
    assert(tlv_list);

    // TODO: consume parsed metadata?

    debugs(47,7, "successful swap meta unpacking; swap_file_sz=" << tmpe.swap_file_sz);
    memset(key, '\0', SQUID_MD5_DIGEST_LENGTH);

    InitStoreEntry visitor(&tmpe, key);
    for_each(*tlv_list, visitor);
    storeSwapTLVFree(tlv_list);
    tlv_list = NULL;

    if (storeKeyNull(key)) {
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring keyless cache entry");
        return false;
    }

    tmpe.key = key;
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

unsigned int
rebuildMaxBlockMsec()
{
    // Balance our desire to maximize the number of entries processed at once
    // (and, hence, minimize overheads and total rebuild time) with a
    // requirement to also process Coordinator events, network I/Os, etc.

    // keep small: most RAM I/Os are under 1ms
    static const unsigned int backgroundMsec = 50;
    // we do not need to react to signals immediately, but this still
    // needs to be small enough to prevent timeouts in waiting workers
    static const unsigned int foregroundMsec = 1000;
    return opt_foreground_rebuild ? foregroundMsec : backgroundMsec;
}

