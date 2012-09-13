/*
 * DEBUG: section 20    Store Rebuild Routines
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
#include "event.h"
#include "globals.h"
#include "md5.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_key_md5.h"
#include "SwapDir.h"
#include "store_digest.h"
#include "store_rebuild.h"
#include "StoreSearch.h"
#include "SquidConfig.h"
#include "SquidTime.h"

#if HAVE_ERRNO_H
#include <errno.h>
#endif
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
storeCleanup(void *datanotused)
{
    static int store_errors = 0;
    static StoreSearchPointer currentSearch;
    static int validated = 0;

    if (currentSearch == NULL || currentSearch->isDone())
        currentSearch = Store::Root().search(NULL, NULL);

    size_t statCount = 500;

    // TODO: Avoid the loop (and ENTRY_VALIDATED) unless opt_store_doublecheck.
    while (statCount-- && !currentSearch->isDone() && currentSearch->next()) {
        StoreEntry *e;

        e = currentSearch->currentItem();

        if (EBIT_TEST(e->flags, ENTRY_VALIDATED))
            continue;

        /*
         * Calling StoreEntry->release() has no effect because we're
         * still in 'store_rebuilding' state
         */
        if (e->swap_filen < 0)
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
    memset(&counts, '\0', sizeof(counts));
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
#include "StoreMetaUnpacker.h"
#include "StoreMeta.h"
#include "Generic.h"

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
            what->lastmod = tmp->lastmod;
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
storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf,
                      StoreRebuildData &counts)
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
                       StoreRebuildData &counts,
                       uint64_t expectedSize)
{
    int swap_hdr_len = 0;
    StoreMetaUnpacker aBuilder(buf.content(), buf.contentSize(), &swap_hdr_len);
    if (aBuilder.isBufferZero()) {
        debugs(47,5, HERE << "skipping empty record.");
        return false;
    }

    if (!aBuilder.isBufferSane()) {
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring malformed cache entry.");
        return false;
    }

    StoreMeta *tlv_list = aBuilder.createStoreMeta();
    if (!tlv_list) {
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring cache entry with invalid " <<
               "meta data");
        return false;
    }

    // TODO: consume parsed metadata?

    debugs(47,7, HERE << "successful swap meta unpacking");
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
        debugs(47, DBG_IMPORTANT, "WARNING: Ignoring cache entry with " <<
               "unknown size: " << tmpe);
        return false;
    }

    if (EBIT_TEST(tmpe.flags, KEY_PRIVATE)) {
        ++ counts.badflags;
        return false;
    }

    return true;
}

bool
storeRebuildKeepEntry(const StoreEntry &tmpe, const cache_key *key,
                      StoreRebuildData &counts)
{
    /* this needs to become
     * 1) unpack url
     * 2) make synthetic request with headers ?? or otherwise search
     * for a matching object in the store
     * TODO FIXME change to new async api
     * TODO FIXME I think there is a race condition here with the
     * async api :
     * store A reads in object foo, searchs for it, and finds nothing.
     * store B reads in object foo, searchs for it, finds nothing.
     * store A gets called back with nothing, so registers the object
     * store B gets called back with nothing, so registers the object,
     * which will conflict when the in core index gets around to scanning
     * store B.
     *
     * this suggests that rather than searching for duplicates, the
     * index rebuild should just assume its the most recent accurate
     * store entry and whoever indexes the stores handles duplicates.
     */
    if (StoreEntry *e = Store::Root().get(key)) {

        if (e->lastref >= tmpe.lastref) {
            /* key already exists, old entry is newer */
            /* keep old, ignore new */
            ++counts.dupcount;

            // For some stores, get() creates/unpacks a store entry. Signal
            // such stores that we will no longer use the get() result:
            e->lock();
            e->unlock();

            return false;
        } else {
            /* URL already exists, this swapfile not being used */
            /* junk old, load new */
            e->release();	/* release old entry */
            ++counts.dupcount;
        }
    }

    return true;
}
