/*
 * $Id: store_digest.cc,v 1.6 1998/04/08 22:52:38 rousskov Exp $
 *
 * DEBUG: section 71    Store Digest Manager
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

/* local types */

typedef struct {
    StoreDigestCBlock cblock;
    int rebuild_lock;		/* bucket number */
    StoreEntry *rewrite_lock;	/* store entry with the digest */
    const char *other_lock;	/* used buy external modules to pause rebuilds and rewrites */
    int rebuild_offset;
    int rewrite_offset;
    int rebuild_count;
    int rewrite_count;
} StoreDigestState;

/*
 * local constants (many of these are good candidates for SquidConfig
 */

/* how often we want to rebuild the digest, seconds */
static const time_t StoreDigestRebuildPeriod = 60 * 60;
/* how often we want to rewrite the digest, seconds */
static const time_t StoreDigestRewritePeriod = 60 * 60;
/* how many bytes to swap out at a time */
static const int StoreDigestSwapOutChunkSize = SM_PAGE_SIZE;
/* portion (0,1] of a hash table to be rescanned at a time */
static const double StoreDigestRebuildChunkPercent = 0.10;

/* local vars */
static StoreDigestState sd_state;

/* local prototypes */
static void storeDigestRebuild(void *datanotused);
static void storeDigestRebuildFinish();
static void storeDigestRebuildStep(void *datanotused);
static void storeDigestRewrite();
static void storeDigestRewriteFinish(StoreEntry * e);
static void storeDigestSwapOutStep(StoreEntry * e);
static void storeDigestCBlockSwapOut(StoreEntry * e);


void
storeDigestInit()
{
    /*
     * To-Do: Bloom proved that the optimal filter utilization is 50% (half of
     * the bits are off). However, we do not have a formula to calculate the 
     * number of _entries_ we want to pre-allocate for.
     * Use 1.5*max#entries because 2*max#entries gives about 40% utilization.
     */
#if SQUID_MAINTAIN_CACHE_DIGEST
    const int cap = (int) (1.5 * Config.Swap.maxSize / Config.Store.avgObjectSize);
    store_digest = cacheDigestCreate(cap);
    debug(71, 1) ("Using %d byte cache digest; rebuild/rewrite every %d/%d sec\n",
	store_digest->mask_size, StoreDigestRebuildPeriod, StoreDigestRewritePeriod);
#else
    store_digest = NULL;
    debug(71, 1) ("Local cache digest is 'off'\n");
#endif
    memset(&sd_state, 0, sizeof(sd_state));
    cachemgrRegister("store_digest", "Store Digest",
	storeDigestReport, 0);
}

void
storeDigestScheduleRebuild()
{
    eventAdd("storeDigestRebuild", storeDigestRebuild, NULL, StoreDigestRebuildPeriod);
}

/* externally initiated rewrite (inits store entry and pauses) */
void
storeDigestRewriteStart() {
    eventAdd("storeDigestRewrite", storeDigestRewrite, NULL, 0);
}

#if OLD_CODE
/* externally initiated rewrite (inits store entry and pauses) */
void
storeDigestRewriteStart(const char *initiator) {
    assert(initiator);
    assert(!sd_state.other_lock);
    sd_state.other_lock = initiator;
    storeDigestRewrite(NULL);
}

/* continue externally initiated rewrite */
void
storeDigestRewriteContinue(const char *initiator)
{
    assert(initiator);
    assert(!strcmp(sd_state.other_lock, initiator));
    assert(sd_state.rewrite_lock);
    sd_state.other_lock = NULL;
    storeDigestSwapOutStep(sd_state.rewrite_lock);
}
#endif /* OLD_CODE */

/* rebuilds digest from scratch */
static void
storeDigestRebuild(void *datanotused)
{
    assert(store_digest);
    /* prevent overlapping if rebuild schedule is too tight */
    if (sd_state.rebuild_lock) {
	debug(71, 1) ("storeDigestRebuild: overlap detected, consider increasing rebuild period\n");
	return;
    }
    sd_state.rebuild_lock = 1;
    sd_state.rebuild_offset = 0;
    /* not clean()! */
    cacheDigestClear(store_digest);
    debug(71, 2) ("storeDigestRebuild: start rebuild #%d\n", sd_state.rebuild_count + 1);
    storeDigestRebuildStep(NULL);
}

/* finishes swap out sequence for the digest; schedules next rebuild */
static void
storeDigestRebuildFinish()
{
    assert(sd_state.rebuild_lock);
    sd_state.rebuild_lock = 0;
    sd_state.rebuild_count++;
    debug(71, 2) ("storeDigestRebuildFinish: done.\n");
    storeDigestScheduleRebuild();
    /* resume pending write if any */
    if (sd_state.rewrite_lock)
	storeDigestSwapOutStep(sd_state.rewrite_lock);
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
	    StoreEntry *e = (StoreEntry *) link_ptr;
	    if (!EBIT_TEST(e->flag, KEY_PRIVATE))
		cacheDigestAdd(store_digest, e->key);
	}
	sd_state.rebuild_offset++;
    }
    /* are we done ? */
    if (sd_state.rebuild_offset >= store_hash_buckets)
	storeDigestRebuildFinish();
    else
	eventAdd("storeDigestRebuildStep", storeDigestRebuildStep, NULL, 0);
}


/* starts swap out sequence for the digest */
static void
storeDigestRewrite(void *datanotused)
{
    int flags;
    StoreEntry *e;
    char *url;

    assert(store_digest);
    /* prevent overlapping if rewrite schedule is too tight */
    if (sd_state.rewrite_lock) {
	debug(71, 1) ("storeDigestRewrite: overlap detected, consider increasing rewrite period\n");
	return;
    }
    debug(71, 2) ("storeDigestRewrite: start rewrite #%d\n", sd_state.rewrite_count + 1);
    /* make new store entry */
    url = urlInternal("", StoreDigestUrlPath);
    flags = 0;
    EBIT_SET(flags, REQ_CACHABLE);
    e = storeCreateEntry(url, url, flags, METHOD_GET);
    assert(e);
    sd_state.rewrite_lock = e;
    sd_state.rewrite_offset = 0;
    EBIT_SET(e->flag, ENTRY_SPECIAL);
    /* setting public key will purge old digest entry if any */
    storeSetPublicKey(e);
    debug(71, 3) ("storeDigestRewrite: url: %s key: %s\n", url, storeKeyText(e->key));
    /* we never unlink it! @?@ @?@ */
    e->mem_obj->request = requestLink(urlParse(METHOD_GET, url));
    /* fake reply */
    httpReplyReset(e->mem_obj->reply);
    httpReplySetHeaders(e->mem_obj->reply, 1.0, 200, "Cache Digest OK",
	"application/cache-digest", store_digest->mask_size + sizeof(sd_state.cblock),
	squid_curtime, squid_curtime + StoreDigestRewritePeriod);
    debug(71, 3) ("storeDigestRewrite: reply.expires = %s\n", mkrfc1123(e->mem_obj->reply->expires));
    storeBuffer(e);
    httpReplySwapOut(e->mem_obj->reply, e);
    storeDigestCBlockSwapOut(e);
    storeBufferFlush(e);
    if (sd_state.other_lock) {
	debug(71, 2) ("storeDigestRewrite: waiting for %s to finish.\n", sd_state.other_lock);
	return;
    }
    storeDigestSwapOutStep(e);
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
    storeUnlockObject(e);
    sd_state.rewrite_lock = e = NULL;
    sd_state.rewrite_count++;
    eventAdd("storeDigestRewrite", storeDigestRewrite, NULL, StoreDigestRewritePeriod);
}

/* swaps out one digest "chunk" per invocation; schedules next swap out */
static void
storeDigestSwapOutStep(StoreEntry * e)
{
    int chunk_size = StoreDigestSwapOutChunkSize;
    assert(e);
    assert(!sd_state.other_lock);
    assert(e == sd_state.rewrite_lock);
    /* wait for rebuild (if any) to finish @?@ */
    if (sd_state.rebuild_lock) {
	debug(71, 2) ("storeDigestRewrite: waiting for rebuild to finish.\n");
	return;
    }
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
	eventAdd("storeDigestSwapOutStep", (EVH *) storeDigestSwapOutStep, e, 0);
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
    storeAppend(e, (char*) &sd_state.cblock, sizeof(sd_state.cblock));
}

void
storeDigestReport(StoreEntry * e)
{
    if (store_digest) {
	cacheDigestReport(store_digest, "store", e);
    } else {
	storeAppendPrintf(e, "store digest: disabled.\n");
    }
}
