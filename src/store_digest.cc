
/*
 * $Id: store_digest.cc,v 1.75 2007/04/30 16:56:09 wessels Exp $
 *
 * DEBUG: section 71    Store Digest Manager
 * AUTHOR: Alex Rousskov
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


/*
 * TODO: We probably do not track all the cases when
 *       storeDigestNoteStoreReady() must be called; this may prevent
 *       storeDigestRebuild/write schedule to be activated
 */

#include "squid.h"
#include "event.h"
#include "CacheManager.h"
#if USE_CACHE_DIGESTS

#include "Store.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "MemObject.h"
#include "PeerDigest.h"
#include "SquidTime.h"
#include "StoreSearch.h"

/*
 * local types
 */

class StoreDigestState
{

public:
    StoreDigestCBlock cblock;
    int rebuild_lock;		/* bucket number */
    StoreEntry * rewrite_lock;	/* points to store entry with the digest */
    StoreSearchPointer theSearch;
    int rewrite_offset;
    int rebuild_count;
    int rewrite_count;
};


typedef struct
{
    int del_count;		/* #store entries deleted from store_digest */
    int del_lost_count;		/* #store entries not found in store_digest on delete */
    int add_count;		/* #store entries accepted to store_digest */
    int add_coll_count;		/* #accepted entries that collided with existing ones */
    int rej_count;		/* #store entries not accepted to store_digest */
    int rej_coll_count;		/* #not accepted entries that collided with existing ones */
}

StoreDigestStats;

/* local vars */
static StoreDigestState sd_state;
static StoreDigestStats sd_stats;

/* local prototypes */
static void storeDigestRebuildStart(void *datanotused);
static void storeDigestRebuildResume(void);
static void storeDigestRebuildFinish(void);
static void storeDigestRebuildStep(void *datanotused);
static void storeDigestRewriteStart(void *);
static void storeDigestRewriteResume(void);
static void storeDigestRewriteFinish(StoreEntry * e);
static EVH storeDigestSwapOutStep;
static void storeDigestCBlockSwapOut(StoreEntry * e);
static int storeDigestCalcCap(void);
static int storeDigestResize(void);
static void storeDigestAdd(const StoreEntry *);

#endif /* USE_CACHE_DIGESTS */

/*
 * PUBLIC FUNCTIONS
 */

void
storeDigestInit(void)
{
#if USE_CACHE_DIGESTS
    const int cap = storeDigestCalcCap();

    if (!Config.onoff.digest_generation) {
        store_digest = NULL;
        debugs(71, 3, "Local cache digest generation disabled");
        return;
    }

    store_digest = cacheDigestCreate(cap, Config.digest.bits_per_entry);
    debugs(71, 1, "Local cache digest enabled; rebuild/rewrite every " <<
           (int) Config.digest.rebuild_period << "/" <<
           (int) Config.digest.rewrite_period << " sec");

    memset(&sd_state, 0, sizeof(sd_state));
#else

    store_digest = NULL;
    debugs(71, 3, "Local cache digest is 'off'");
#endif
}

void
storeDigestRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("store_digest", "Store Digest",
                           storeDigestReport, 0, 1);
}

/* called when store_rebuild completes */
void
storeDigestNoteStoreReady(void)
{
#if USE_CACHE_DIGESTS

    if (Config.onoff.digest_generation) {
        storeDigestRebuildStart(NULL);
        storeDigestRewriteStart(NULL);
    }

#endif
}

void
storeDigestDel(const StoreEntry * entry)
{
#if USE_CACHE_DIGESTS

    if (!Config.onoff.digest_generation) {
        return;
    }

    assert(entry && store_digest);
    debugs(71, 6, "storeDigestDel: checking entry, key: " << entry->getMD5Text());

    if (!EBIT_TEST(entry->flags, KEY_PRIVATE)) {
        if (!cacheDigestTest(store_digest,  (const cache_key *)entry->key)) {
            sd_stats.del_lost_count++;
            debugs(71, 6, "storeDigestDel: lost entry, key: " << entry->getMD5Text() << " url: " << entry->url()  );
        } else {
            sd_stats.del_count++;
            cacheDigestDel(store_digest,  (const cache_key *)entry->key);
            debugs(71, 6, "storeDigestDel: deled entry, key: " << entry->getMD5Text());
        }
    }

#endif
}

void
storeDigestReport(StoreEntry * e)
{
#if USE_CACHE_DIGESTS

    if (!Config.onoff.digest_generation) {
        return;
    }

    if (store_digest) {
        cacheDigestReport(store_digest, "store", e);
        storeAppendPrintf(e, "\t added: %d rejected: %d ( %.2f %%) del-ed: %d\n",
                          sd_stats.add_count,
                          sd_stats.rej_count,
                          xpercent(sd_stats.rej_count, sd_stats.rej_count + sd_stats.add_count),
                          sd_stats.del_count);
        storeAppendPrintf(e, "\t collisions: on add: %.2f %% on rej: %.2f %%\n",
                          xpercent(sd_stats.add_coll_count, sd_stats.add_count),
                          xpercent(sd_stats.rej_coll_count, sd_stats.rej_count));
    } else {
        storeAppendPrintf(e, "store digest: disabled.\n");
    }

#endif
}

/*
 * LOCAL FUNCTIONS
 */

#if USE_CACHE_DIGESTS

/* should we digest this entry? used by storeDigestAdd() */
static int
storeDigestAddable(const StoreEntry * e)
{
    /* add some stats! XXX */

    debugs(71, 6, "storeDigestAddable: checking entry, key: " << e->getMD5Text());

    /* check various entry flags (mimics StoreEntry::checkCachable XXX) */

    if (!EBIT_TEST(e->flags, ENTRY_CACHABLE)) {
        debugs(71, 6, "storeDigestAddable: NO: not cachable");
        return 0;
    }

    if (EBIT_TEST(e->flags, KEY_PRIVATE)) {
        debugs(71, 6, "storeDigestAddable: NO: private key");
        return 0;
    }

    if (EBIT_TEST(e->flags, ENTRY_NEGCACHED)) {
        debugs(71, 6, "storeDigestAddable: NO: negative cached");
        return 0;
    }

    if (EBIT_TEST(e->flags, RELEASE_REQUEST)) {
        debugs(71, 6, "storeDigestAddable: NO: release requested");
        return 0;
    }

    if (e->store_status == STORE_OK && EBIT_TEST(e->flags, ENTRY_BAD_LENGTH)) {
        debugs(71, 6, "storeDigestAddable: NO: wrong content-length");
        return 0;
    }

    /* do not digest huge objects */
    if (e->swap_file_sz > Config.Store.maxObjectSize) {
        debugs(71, 6, "storeDigestAddable: NO: too big");
        return 0;
    }

    /* still here? check staleness */
    /* Note: We should use the time of the next rebuild, not (cur_time+period) */
    if (refreshCheckDigest(e, Config.digest.rebuild_period)) {
        debugs(71, 6, "storeDigestAdd: entry expires within " << Config.digest.rebuild_period << " secs, ignoring");
        return 0;
    }

    /*
     * idea: how about also skipping very fresh (thus, potentially
     * unstable) entries? Should be configurable through
     * cd_refresh_pattern, of course.
     */
    /*
     * idea: skip objects that are going to be purged before the next
     * update.
     */
    return 1;
}

static void
storeDigestAdd(const StoreEntry * entry)
{
    assert(entry && store_digest);

    if (storeDigestAddable(entry)) {
        sd_stats.add_count++;

        if (cacheDigestTest(store_digest, (const cache_key *)entry->key))
            sd_stats.add_coll_count++;

        cacheDigestAdd(store_digest,  (const cache_key *)entry->key);

        debugs(71, 6, "storeDigestAdd: added entry, key: " << entry->getMD5Text());
    } else {
        sd_stats.rej_count++;

        if (cacheDigestTest(store_digest,  (const cache_key *)entry->key))
            sd_stats.rej_coll_count++;
    }
}

/* rebuilds digest from scratch */
static void
storeDigestRebuildStart(void *datanotused)
{
    assert(store_digest);
    /* prevent overlapping if rebuild schedule is too tight */

    if (sd_state.rebuild_lock) {
        debugs(71, 1, "storeDigestRebuildStart: overlap detected, consider increasing rebuild period");
        return;
    }

    sd_state.rebuild_lock = 1;
    debugs(71, 2, "storeDigestRebuildStart: rebuild #" << sd_state.rebuild_count + 1);

    if (sd_state.rewrite_lock) {
        debugs(71, 2, "storeDigestRebuildStart: waiting for Rewrite to finish.");
        return;
    }

    storeDigestRebuildResume();
}

/* called be Rewrite to push Rebuild forward */
static void
storeDigestRebuildResume(void)
{
    assert(sd_state.rebuild_lock);
    assert(!sd_state.rewrite_lock);
    sd_state.theSearch = Store::Root().search(NULL, NULL);
    /* resize or clear */

    if (!storeDigestResize())
        cacheDigestClear(store_digest);		/* not clean()! */

    memset(&sd_stats, 0, sizeof(sd_stats));

    eventAdd("storeDigestRebuildStep", storeDigestRebuildStep, NULL, 0.0, 1);
}

/* finishes swap out sequence for the digest; schedules next rebuild */
static void
storeDigestRebuildFinish(void)
{
    assert(sd_state.rebuild_lock);
    sd_state.rebuild_lock = 0;
    sd_state.rebuild_count++;
    debugs(71, 2, "storeDigestRebuildFinish: done.");
    eventAdd("storeDigestRebuildStart", storeDigestRebuildStart, NULL, (double)
             Config.digest.rebuild_period, 1);
    /* resume pending Rewrite if any */

    if (sd_state.rewrite_lock)
        storeDigestRewriteResume();
}

/* recalculate a few hash buckets per invocation; schedules next step */
static void
storeDigestRebuildStep(void *datanotused)
{
    /* TODO: call Store::Root().size() to determine this.. */
    int count = Config.Store.objectsPerBucket * (int) ceil((double) store_hash_buckets *
                (double) Config.digest.rebuild_chunk_percentage / 100.0);
    assert(sd_state.rebuild_lock);

    debugs(71, 3, "storeDigestRebuildStep: buckets: " << store_hash_buckets << " entries to check: " << count);

    while (count-- && !sd_state.theSearch->isDone() && sd_state.theSearch->next())
        storeDigestAdd(sd_state.theSearch->currentItem());

    /* are we done ? */
    if (sd_state.theSearch->isDone())
        storeDigestRebuildFinish();
    else
        eventAdd("storeDigestRebuildStep", storeDigestRebuildStep, NULL, 0.0, 1);
}


/* starts swap out sequence for the digest */
static void
storeDigestRewriteStart(void *datanotused)
{
    request_flags flags;
    char *url;
    StoreEntry *e;

    assert(store_digest);
    /* prevent overlapping if rewrite schedule is too tight */

    if (sd_state.rewrite_lock) {
        debugs(71, 1, "storeDigestRewrite: overlap detected, consider increasing rewrite period");
        return;
    }

    debugs(71, 2, "storeDigestRewrite: start rewrite #" << sd_state.rewrite_count + 1);
    /* make new store entry */
    url = internalLocalUri("/squid-internal-periodic/", StoreDigestFileName);
    flags.cachable = 1;
    e = storeCreateEntry(url, url, flags, METHOD_GET);
    assert(e);
    sd_state.rewrite_lock = e;
    debugs(71, 3, "storeDigestRewrite: url: " << url << " key: " << e->getMD5Text());
    HttpRequest *req = HttpRequest::CreateFromUrl(url);
    e->mem_obj->request = HTTPMSGLOCK(req);
    /* wait for rebuild (if any) to finish */

    if (sd_state.rebuild_lock) {
        debugs(71, 2, "storeDigestRewriteStart: waiting for rebuild to finish.");
        return;
    }

    storeDigestRewriteResume();
}

static void
storeDigestRewriteResume(void)
{
    StoreEntry *e;

    assert(sd_state.rewrite_lock);
    assert(!sd_state.rebuild_lock);
    e = sd_state.rewrite_lock;
    sd_state.rewrite_offset = 0;
    EBIT_SET(e->flags, ENTRY_SPECIAL);
    /* setting public key will purge old digest entry if any */
    e->setPublicKey();
    /* fake reply */
    HttpReply *rep = new HttpReply;
    HttpVersion version(1, 0);
    rep->setHeaders(version, HTTP_OK, "Cache Digest OK",
                    "application/cache-digest", store_digest->mask_size + sizeof(sd_state.cblock),
                    squid_curtime, squid_curtime + Config.digest.rewrite_period);
    debugs(71, 3, "storeDigestRewrite: entry expires on " << rep->expires << 
           " (" << std::showpos << (int) (rep->expires - squid_curtime) << ")");
    e->buffer();
    e->replaceHttpReply(rep);
    storeDigestCBlockSwapOut(e);
    e->flush();
    eventAdd("storeDigestSwapOutStep", storeDigestSwapOutStep, sd_state.rewrite_lock, 0.0, 1, false);
}

/* finishes swap out sequence for the digest; schedules next rewrite */
static void
storeDigestRewriteFinish(StoreEntry * e)
{
    assert(e == sd_state.rewrite_lock);
    e->complete();
    e->timestampsSet();
    debugs(71, 2, "storeDigestRewriteFinish: digest expires at " << e->expires << 
           " (" << std::showpos << (int) (e->expires - squid_curtime) << ")");
    /* is this the write order? @?@ */
    e->mem_obj->unlinkRequest();
    e->unlock();
    sd_state.rewrite_lock = NULL;
    sd_state.rewrite_count++;
    eventAdd("storeDigestRewriteStart", storeDigestRewriteStart, NULL, (double)
             Config.digest.rewrite_period, 1);
    /* resume pending Rebuild if any */

    if (sd_state.rebuild_lock)
        storeDigestRebuildResume();
}

/* swaps out one digest "chunk" per invocation; schedules next swap out */
static void
storeDigestSwapOutStep(void *data)
{
    StoreEntry *e = static_cast<StoreEntry *>(data);
    int chunk_size = Config.digest.swapout_chunk_size;
    assert(e == sd_state.rewrite_lock);
    assert(e);
    /* _add_ check that nothing bad happened while we were waiting @?@ @?@ */

    if ((size_t)(sd_state.rewrite_offset + chunk_size) > store_digest->mask_size)
        chunk_size = store_digest->mask_size - sd_state.rewrite_offset;

    e->append(store_digest->mask + sd_state.rewrite_offset, chunk_size);

    debugs(71, 3, "storeDigestSwapOutStep: size: " << store_digest->mask_size <<
           " offset: " << sd_state.rewrite_offset << " chunk: " <<
           chunk_size << " bytes");

    sd_state.rewrite_offset += chunk_size;

    /* are we done ? */
    if ((size_t)sd_state.rewrite_offset >= store_digest->mask_size)
        storeDigestRewriteFinish(e);
    else
        eventAdd("storeDigestSwapOutStep", storeDigestSwapOutStep, data, 0.0, 1, false);
}

static void
storeDigestCBlockSwapOut(StoreEntry * e)
{
    memset(&sd_state.cblock, 0, sizeof(sd_state.cblock));
    sd_state.cblock.ver.current = htons(CacheDigestVer.current);
    sd_state.cblock.ver.required = htons(CacheDigestVer.required);
    sd_state.cblock.capacity = htonl(store_digest->capacity);
    sd_state.cblock.count = htonl(store_digest->count);
    sd_state.cblock.del_count = htonl(store_digest->del_count);
    sd_state.cblock.mask_size = htonl(store_digest->mask_size);
    sd_state.cblock.bits_per_entry = (unsigned char)
                                     Config.digest.bits_per_entry;
    sd_state.cblock.hash_func_count = (unsigned char) CacheDigestHashFuncCount;
    e->append((char *) &sd_state.cblock, sizeof(sd_state.cblock));
}

/* calculates digest capacity */
static int
storeDigestCalcCap(void)
{
    /*
     * To-Do: Bloom proved that the optimal filter utilization is 50% (half of
     * the bits are off). However, we do not have a formula to calculate the 
     * number of _entries_ we want to pre-allocate for.
     */
    const int hi_cap = Store::Root().maxSize() / Config.Store.avgObjectSize;
    const int lo_cap = 1 + store_swap_size / Config.Store.avgObjectSize;
    const int e_count = StoreEntry::inUseCount();
    int cap = e_count ? e_count : hi_cap;
    debugs(71, 2, "storeDigestCalcCap: have: " << e_count << ", want " << cap <<
           " entries; limits: [" << lo_cap << ", " << hi_cap << "]");

    if (cap < lo_cap)
        cap = lo_cap;

    /* do not enforce hi_cap limit, average-based estimation may be wrong
     *if (cap > hi_cap)
     *  cap = hi_cap; 
     */
    return cap;
}

/* returns true if we actually resized the digest */
static int
storeDigestResize(void)
{
    const int cap = storeDigestCalcCap();
    int diff;
    assert(store_digest);
    diff = abs(cap - store_digest->capacity);
    debugs(71, 2, "storeDigestResize: " << 
           store_digest->capacity << " -> " << cap << "; change: " << 
           diff << " (" << xpercentInt(diff, store_digest->capacity) << "%)" );
    /* avoid minor adjustments */

    if (diff <= store_digest->capacity / 10) {
        debugs(71, 2, "storeDigestResize: small change, will not resize.");
        return 0;
    } else {
        debugs(71, 2, "storeDigestResize: big change, resizing.");
        cacheDigestChangeCap(store_digest, cap);
        return 1;
    }
}

#endif /* USE_CACHE_DIGESTS */
