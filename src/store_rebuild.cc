
/*
 * $Id$
 *
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
#include "Store.h"
#include "SwapDir.h"
#include "StoreSearch.h"
#include "SquidTime.h"

static struct _store_rebuild_data counts;

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

    while (statCount-- && !currentSearch->isDone() && currentSearch->next()) {
        ++validated;
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
                store_errors++;

        EBIT_SET(e->flags, ENTRY_VALIDATED);

        /*
         * Only set the file bit if we know its a valid entry
         * otherwise, set it in the validation procedure
         */
        e->store()->updateSize(e->swap_file_sz, 1);

        if ((++validated & 0x3FFFF) == 0)
            /* TODO format the int with with a stream operator */
            debugs(20, 1, "  " << validated << " Entries Validated so far.");
    }

    if (currentSearch->isDone()) {
        debugs(20, 1, "  Completed Validation Procedure");
        debugs(20, 1, "  Validated " << validated << " Entries");
        debugs(20, 1, "  store_swap_size = " << store_swap_size);
        StoreController::store_dirs_rebuilding--;
        assert(0 == StoreController::store_dirs_rebuilding);

        if (opt_store_doublecheck)
            assert(store_errors == 0);

        if (store_digest)
            storeDigestNoteStoreReady();

        currentSearch = NULL;
    } else
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

    if (StoreController::store_dirs_rebuilding > 1)
        return;

    dt = tvSubDsec(rebuild_start, current_time);

    debugs(20, 1, "Finished rebuilding storage from disk.");
    debugs(20, 1, "  " << std::setw(7) << counts.scancount  << " Entries scanned");
    debugs(20, 1, "  " << std::setw(7) << counts.invalid  << " Invalid entries.");
    debugs(20, 1, "  " << std::setw(7) << counts.badflags  << " With invalid flags.");
    debugs(20, 1, "  " << std::setw(7) << counts.objcount  << " Objects loaded.");
    debugs(20, 1, "  " << std::setw(7) << counts.expcount  << " Objects expired.");
    debugs(20, 1, "  " << std::setw(7) << counts.cancelcount  << " Objects cancelled.");
    debugs(20, 1, "  " << std::setw(7) << counts.dupcount  << " Duplicate URLs purged.");
    debugs(20, 1, "  " << std::setw(7) << counts.clashcount  << " Swapfile clashes avoided.");
    debugs(20, 1, "  Took "<< std::setw(3)<< std::setprecision(2) << dt << " seconds ("<< std::setw(6) <<
           ((double) counts.objcount / (dt > 0.0 ? dt : 1.0)) << " objects/sec).");
    debugs(20, 1, "Beginning Validation Procedure");

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

    for (sd_index = 0; sd_index < Config.cacheSwap.n_configured; sd_index++) {
        n += (double) RebuildProgress[sd_index].scanned;
        d += (double) RebuildProgress[sd_index].total;
    }

    debugs(20, 1, "Store rebuilding is "<< std::setw(4)<< std::setprecision(2) << 100.0 * n / d << "% complete");
    last_report = squid_curtime;
}
