/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#include "squid.h"
#include "event.h"
#include "globals.h"
#include "md5.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "store/Disk.h"
#include "store_digest.h"
#include "store_key_md5.h"
#include "store_rebuild.h"
#include "StoreSearch.h"
// for tvSubDsec() which should be in SquidTime.h
#include "util.h"

#include <cerrno>

static StoreRebuildData counts;

static struct timeval rebuild_start;
static void storeCleanup(void *);

typedef struct {
    /* total number of "swap.state" entries that will be read */
    int total;
    /* number of entries read so far */
    int scanned;
} store_rebuild_progress;

static store_rebuild_progress *RebuildProgress = NULL;

static int
storeCleanupDoubleCheck(StoreEntry * e)
{
    SwapDir *SD = dynamic_cast<SwapDir *>(INDEXSD(e->swap_dirn));
    return (SD->doubleCheck(*e));
}

static void
storeCleanup(void *)
{
    static int store_errors = 0;
    static StoreSearchPointer currentSearch;
    static int validated = 0;
    static int seen = 0;

    if (currentSearch == NULL || currentSearch->isDone())
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
            if (storeCleanupDoubleCheck(e))
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
        debugs(20, DBG_IMPORTANT, "  Completed Validation Procedure");
        debugs(20, DBG_IMPORTANT, "  Validated " << validated << " Entries");
        debugs(20, DBG_IMPORTANT, "  store_swap_size = " << Store::Root().currentSize() / 1024.0 << " KB");
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

        currentSearch = NULL;
    } else
        eventAdd("storeCleanup", storeCleanup, NULL, 0.0, 1);
}

/* meta data recreated from disk image in swap directory */
void

storeRebuildComplete(StoreRebuildData *dc)
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

    if (StoreController::store_dirs_rebuilding > 1)
        return;

    dt = tvSubDsec(rebuild_start, current_time);

    debugs(20, DBG_IMPORTANT, "Finished rebuilding storage from disk.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.scancount  << " Entries scanned");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.invalid  << " Invalid entries.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.badflags  << " With invalid flags.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.objcount  << " Objects loaded.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.expcount  << " Objects expired.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.cancelcount  << " Objects cancelled.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.dupcount  << " Duplicate URLs purged.");
    debugs(20, DBG_IMPORTANT, "  " << std::setw(7) << counts.clashcount  << " Swapfile clashes avoided.");
    debugs(20, DBG_IMPORTANT, "  Took "<< std::setw(3)<< std::setprecision(2) << dt << " seconds ("<< std::setw(6) <<
           ((double) counts.objcount / (dt > 0.0 ? dt : 1.0)) << " objects/sec).");
    debugs(20, DBG_IMPORTANT, "Beginning Validation Procedure");

    eventAdd("storeCleanup", storeCleanup, NULL, 0.0, 1);

    xfree(RebuildProgress);

    RebuildProgress = NULL;
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
    rebuild_start = current_time;
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
    double n = 0.0;
    double d = 0.0;

    if (sd_index < 0)
        return;

    if (sd_index >= Config.cacheSwap.n_configured)
        return;

    if (NULL == RebuildProgress)
        return;

    RebuildProgress[sd_index].total = total;

    RebuildProgress[sd_index].scanned = sofar;

    if (squid_curtime - last_report < 15)
        return;

    for (sd_index = 0; sd_index < Config.cacheSwap.n_configured; ++sd_index) {
        n += (double) RebuildProgress[sd_index].scanned;
        d += (double) RebuildProgress[sd_index].total;
    }

    debugs(20, DBG_IMPORTANT, "Store rebuilding is "<< std::setw(4)<< std::setprecision(2) << 100.0 * n / d << "% complete");
    last_report = squid_curtime;
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

