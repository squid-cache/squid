/*
 * $Id: store_digest.cc,v 1.28 1998/09/19 17:06:13 wessels Exp $
 *
 * DEBUG: section 71    Store Digest Manager
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

#if USE_CACHE_DIGESTS

/*
 * local types
 */

typedef struct {
    StoreDigestCBlock cblock;
    int rebuild_lock;		/* bucket number */
    StoreEntry *rewrite_lock;	/* store entry with the digest */
    int rebuild_offset;
    int rewrite_offset;
    int rebuild_count;
    int rewrite_count;
} StoreDigestState;

typedef struct {
    int del_count;		/* #store entries deleted from store_digest */
    int del_lost_count;		/* #store entries not found in store_digest on delete */
    int add_count;		/* #store entries accepted to store_digest */
    int add_coll_count;		/* #accepted entries that collided with existing ones */
    int rej_count;		/* #store entries not accepted to store_digest */
    int rej_coll_count;		/* #not accepted entries that collided with existing ones */
} StoreDigestStats;

/*
 * local constants (many of these are good candidates for SquidConfig
 */

/* #bits per entry in store digest */
static const int StoreDigestBitsPerEntry = 5;
/* how often we want to rebuild the digest, in seconds */
static const time_t StoreDigestRebuildPeriod = 60 * 60;
/* how often we want to rewrite the digest after rebuild, in seconds */
static const int StoreDigestRewritePeriod = 60 * 60;
/* how many bytes to swap out at a time */
static const int StoreDigestSwapOutChunkSize = SM_PAGE_SIZE;
/* portion (0,1] of a hash table to be rescanned at a time */
static const double StoreDigestRebuildChunkPercent = 0.10;

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
    store_digest = cacheDigestCreate(cap, StoreDigestBitsPerEntry);
    debug(71, 1) ("Local cache digest enabled; rebuild/rewrite every %d/%d sec\n",
	StoreDigestRebuildPeriod, StoreDigestRewritePeriod);
    memset(&sd_state, 0, sizeof(sd_state));
    cachemgrRegister("store_digest", "Store Digest",
	storeDigestReport, 0, 1);
#else
    store_digest = NULL;
    debug(71, 3) ("Local cache digest is 'off'\n");
#endif
}

/* called when store_rebuild completes */
void
storeDigestNoteStoreReady(void)
{
#if USE_CACHE_DIGESTS
    storeDigestRebuildStart(NULL);
    storeDigestRewriteStart(NULL);
#endif
}

void
storeDigestDel(const StoreEntry * entry)
{
#if USE_CACHE_DIGESTS
    assert(entry && store_digest);
    debug(71, 6) ("storeDigestDel: checking entry, key: %s\n",
	storeKeyText(entry->key));
    if (!EBIT_TEST(entry->flags, KEY_PRIVATE)) {
	if (!cacheDigestTest(store_digest, entry->key)) {
	    sd_stats.del_lost_count++;
	    debug(71, 6) ("storeDigestDel: lost entry, key: %s url: %s\n",
		storeKeyText(entry->key), storeUrl(entry));
	} else {
	    sd_stats.del_count++;
	    cacheDigestDel(store_digest, entry->key);
	    debug(71, 6) ("storeDigestDel: deled entry, key: %s\n",
		storeKeyText(entry->key));
	}
    }
#endif
}

void
storeDigestReport(StoreEntry * e)
{
#if USE_CACHE_DIGESTS
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

static void
storeDigestAdd(const StoreEntry * entry)
{
    int good_entry = 0;
    assert(entry && store_digest);
    debug(71, 6) ("storeDigestAdd: checking entry, key: %s\n",
	storeKeyText(entry->key));
    /* only public entries are digested */
    if (!EBIT_TEST(entry->flags, KEY_PRIVATE)) {
	const time_t refresh = refreshWhen(entry);
	debug(71, 6) ("storeDigestAdd: entry expires in %d secs\n",
	    (int) (refresh - squid_curtime));
	/* if expires too soon, ignore */
	/* Note: We should use the time of the next rebuild, not cur_time @?@ */
	if (refresh <= squid_curtime + StoreDigestRebuildPeriod) {
	    debug(71, 6) ("storeDigestAdd: entry expires too early, ignoring\n");
	} else {
	    good_entry = 1;
	}
    }
    if (good_entry) {
	sd_stats.add_count++;
	if (cacheDigestTest(store_digest, entry->key))
	    sd_stats.add_coll_count++;
	cacheDigestAdd(store_digest, entry->key);
	debug(71, 6) ("storeDigestAdd: added entry, key: %s\n",
	    storeKeyText(entry->key));
    } else {
	sd_stats.rej_count++;
	if (cacheDigestTest(store_digest, entry->key))
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
	debug(71, 1) ("storeDigestRebuildStart: overlap detected, consider increasing rebuild period\n");
	return;
    }
    sd_state.rebuild_lock = 1;
    debug(71, 2) ("storeDigestRebuildStart: rebuild #%d\n", sd_state.rebuild_count + 1);
    if (sd_state.rewrite_lock) {
	debug(71, 2) ("storeDigestRebuildStart: waiting for Rewrite to finish.\n");
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
    sd_state.rebuild_offset = 0;
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
    debug(71, 2) ("storeDigestRebuildFinish: done.\n");
    eventAdd("storeDigestRebuildStart", storeDigestRebuildStart, NULL, (double) StoreDigestRebuildPeriod, 1);
    /* resume pending Rewrite if any */
    if (sd_state.rewrite_lock)
	storeDigestRewriteResume();
}

/* recalculate a few hash buckets per invocation; schedules next step */
static void
storeDigestRebuildStep(void *datanotused)
{
    int bcount = (int) ceil(store_hash_buckets * StoreDigestRebuildChunkPercent);
    assert(sd_state.rebuild_lock);
    if (sd_state.rebuild_offset + bcount > store_hash_buckets)
	bcount = store_hash_buckets - sd_state.rebuild_offset;
    debug(71, 3) ("storeDigestRebuildStep: buckets: %d offset: %d chunk: %d buckets\n",
	store_hash_buckets, sd_state.rebuild_offset, bcount);
    while (bcount--) {
	hash_link *link_ptr = hash_get_bucket(store_table, sd_state.rebuild_offset);
	for (; link_ptr; link_ptr = link_ptr->next) {
	    storeDigestAdd((StoreEntry *) link_ptr);
	}
	sd_state.rebuild_offset++;
    }
    /* are we done ? */
    if (sd_state.rebuild_offset >= store_hash_buckets)
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
	debug(71, 1) ("storeDigestRewrite: overlap detected, consider increasing rewrite period\n");
	return;
    }
    debug(71, 2) ("storeDigestRewrite: start rewrite #%d\n", sd_state.rewrite_count + 1);
    /* make new store entry */
    url = internalLocalUri("/squid-internal-periodic/", StoreDigestUrlPath);
    flags = null_request_flags;
    flags.cachable = 1;
    sd_state.rewrite_lock = e = storeCreateEntry(url, url, flags, METHOD_GET);
    assert(sd_state.rewrite_lock);
    cbdataAdd(sd_state.rewrite_lock, MEM_DONTFREE);
    debug(71, 3) ("storeDigestRewrite: url: %s key: %s\n", url, storeKeyText(e->key));
    e->mem_obj->request = requestLink(urlParse(METHOD_GET, url));
    /* wait for rebuild (if any) to finish */
    if (sd_state.rebuild_lock) {
	debug(71, 2) ("storeDigestRewriteStart: waiting for rebuild to finish.\n");
	return;
    }
    storeDigestRewriteResume();
}

static void
storeDigestRewriteResume(void)
{
    StoreEntry *e = sd_state.rewrite_lock;

    assert(sd_state.rewrite_lock);
    assert(!sd_state.rebuild_lock);
    sd_state.rewrite_offset = 0;
    EBIT_SET(e->flags, ENTRY_SPECIAL);
    /* setting public key will purge old digest entry if any */
    storeSetPublicKey(e);
    /* fake reply */
    httpReplyReset(e->mem_obj->reply);
    httpReplySetHeaders(e->mem_obj->reply, 1.0, 200, "Cache Digest OK",
	"application/cache-digest", store_digest->mask_size + sizeof(sd_state.cblock),
	squid_curtime, squid_curtime + StoreDigestRewritePeriod);
    debug(71, 3) ("storeDigestRewrite: entry expires on %s\n", mkrfc1123(e->mem_obj->reply->expires));
    storeBuffer(e);
    httpReplySwapOut(e->mem_obj->reply, e);
    storeDigestCBlockSwapOut(e);
    storeBufferFlush(e);
    eventAdd("storeDigestSwapOutStep", storeDigestSwapOutStep, sd_state.rewrite_lock, 0.0, 1);
}

/* finishes swap out sequence for the digest; schedules next rewrite */
static void
storeDigestRewriteFinish(StoreEntry * e)
{
    assert(e == sd_state.rewrite_lock);
    storeComplete(e);
    storeTimestampsSet(e);
    debug(71, 2) ("storeDigestRewriteFinish: digest expires on %s (%d)\n",
	mkrfc1123(e->expires), e->expires);
    /* is this the write order? @?@ */
    requestUnlink(e->mem_obj->request);
    e->mem_obj->request = NULL;
    storeUnlockObject(e);
    /*
     * note, it won't really get free()'d here because we used
     * MEM_DONTFREE in the call to cbdataAdd().
     */
    cbdataFree(sd_state.rewrite_lock);
    sd_state.rewrite_lock = e = NULL;
    sd_state.rewrite_count++;
    eventAdd("storeDigestRewriteStart", storeDigestRewriteStart, NULL, (double) StoreDigestRewritePeriod, 1);
    /* resume pending Rebuild if any */
    if (sd_state.rebuild_lock)
	storeDigestRebuildResume();
}

/* swaps out one digest "chunk" per invocation; schedules next swap out */
static void
storeDigestSwapOutStep(void *data)
{
    StoreEntry *e = data;
    int chunk_size = StoreDigestSwapOutChunkSize;
    assert(e);
    assert(e == sd_state.rewrite_lock);
    /* _add_ check that nothing bad happened while we were waiting @?@ @?@ */
    if (sd_state.rewrite_offset + chunk_size > store_digest->mask_size)
	chunk_size = store_digest->mask_size - sd_state.rewrite_offset;
    storeAppend(e, store_digest->mask + sd_state.rewrite_offset, chunk_size);
    debug(71, 3) ("storeDigestSwapOutStep: size: %d offset: %d chunk: %d bytes\n",
	store_digest->mask_size, sd_state.rewrite_offset, chunk_size);
    sd_state.rewrite_offset += chunk_size;
    /* are we done ? */
    if (sd_state.rewrite_offset >= store_digest->mask_size)
	storeDigestRewriteFinish(e);
    else
	eventAdd("storeDigestSwapOutStep", storeDigestSwapOutStep, e, 0.0, 1);
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
    sd_state.cblock.bits_per_entry = (unsigned char) StoreDigestBitsPerEntry;
    sd_state.cblock.hash_func_count = (unsigned char) CacheDigestHashFuncCount;
    storeAppend(e, (char *) &sd_state.cblock, sizeof(sd_state.cblock));
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
    const int hi_cap = Config.Swap.maxSize / Config.Store.avgObjectSize;
    const int lo_cap = 1 + store_swap_size / Config.Store.avgObjectSize;
    const int e_count = memInUse(MEM_STOREENTRY);
    int cap = e_count ? e_count : hi_cap;
    debug(71, 2) ("storeDigestCalcCap: have: %d, want %d entries; limits: [%d, %d]\n",
	e_count, cap, lo_cap, hi_cap);
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
    debug(71, 2) ("storeDigestResize: %d -> %d; change: %d (%d%%)\n",
	store_digest->capacity, cap, diff,
	xpercentInt(diff, store_digest->capacity));
    /* avoid minor adjustments */
    if (diff <= store_digest->capacity / 10) {
	debug(71, 2) ("storeDigestResize: small change, will not resize.\n");
	return 0;
    } else {
	debug(71, 2) ("storeDigestResize: big change, resizing.\n");
	cacheDigestChangeCap(store_digest, cap);
	return 1;
    }
}

#endif /* USE_CACHE_DIGESTS */
