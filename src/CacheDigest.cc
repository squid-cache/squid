
/*
 * $Id: CacheDigest.cc,v 1.13 1998/04/14 16:38:21 rousskov Exp $
 *
 * DEBUG: section 70    Cache Digest
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
    int bit_count;		/* total number of bits */
    int bit_on_count;		/* #bits turned on */
    int bseq_len_sum;		/* sum of all bit seq length */
    int bseq_count;		/* number of bit seqs */
} CacheDigestStats;

/* local functions */
static void cacheDigestHashKey(const CacheDigest *cd, const cache_key *key);
static size_t cacheDigestCalcMaskSize(int cap);

/* configuration params */
static const int BitsPerEntry = 4;

/* static array used by cacheDigestHashKey for optimization purposes */
static u_num32 hashed_keys[4];


CacheDigest *
cacheDigestCreate(int capacity)
{
    const size_t mask_size = cacheDigestCalcMaskSize(capacity);
    CacheDigest *cd = cacheDigestSizedCreate(mask_size, capacity);
    return cd;
}

/* use this method only if mask size is known a priory */
CacheDigest *
cacheDigestSizedCreate(size_t size, int capacity)
{
    CacheDigest *cd = memAllocate(MEM_CACHE_DIGEST);
    assert(MD5_DIGEST_CHARS == 16);	/* our hash functions rely on 16 byte keys */
    assert(capacity > 0);
    cd->capacity = capacity;
    cd->mask_size = size;
    cd->mask = xcalloc(cd->mask_size, 1);
    return cd;
}

void
cacheDigestDestroy(CacheDigest * cd)
{
    assert(cd);
    xfree(cd->mask);
    xfree(cd);
}

CacheDigest *
cacheDigestClone(const CacheDigest * cd)
{
    CacheDigest *clone;
    assert(cd);
    clone = cacheDigestCreate(cd->capacity);
    clone->count = cd->count;
    xmemcpy(clone->mask, cd->mask, cd->mask_size);
    return clone;
}

void
cacheDigestClear(CacheDigest * cd)
{
    assert(cd);
    cd->count = cd->del_count = 0;
    memset(cd->mask, 0, cd->mask_size);
}

void
cacheDigestChangeCap(CacheDigest * cd, int new_cap)
{
    assert(cd);
    /* have to clear because capacity changes hash functions */
    cacheDigestClear(cd);
    cd->capacity = new_cap;
    cd->mask_size = cacheDigestCalcMaskSize(new_cap);
    cd->mask = xrealloc(cd->mask, cd->mask_size);
}

/* returns true if the key belongs to the digest */
int
cacheDigestTest(const CacheDigest * cd, const cache_key * key)
{
    assert(cd && key);
    /* hash */
    cacheDigestHashKey(cd, key);
    /* test corresponding bits */
    return
	CBIT_TEST(cd->mask, hashed_keys[0]) &&
	CBIT_TEST(cd->mask, hashed_keys[1]) &&
	CBIT_TEST(cd->mask, hashed_keys[2]) &&
	CBIT_TEST(cd->mask, hashed_keys[3]);
}

void
cacheDigestAdd(CacheDigest * cd, const cache_key * key)
{
    assert(cd && key);
    /* hash */
    cacheDigestHashKey(cd, key);
    /* turn on corresponding bits */
#if CD_FAST_ADD
    CBIT_SET(cd->mask, hashed_keys[0]);
    CBIT_SET(cd->mask, hashed_keys[1]);
    CBIT_SET(cd->mask, hashed_keys[2]);
    CBIT_SET(cd->mask, hashed_keys[3]);
#else
    {
	int on_xition_cnt = 0;
	if (!CBIT_TEST(cd->mask, hashed_keys[0])) {
	    CBIT_SET(cd->mask, hashed_keys[0]);
	    on_xition_cnt++;
	}
	if (!CBIT_TEST(cd->mask, hashed_keys[1])) {
	    CBIT_SET(cd->mask, hashed_keys[1]);
	    on_xition_cnt++;
	}
	if (!CBIT_TEST(cd->mask, hashed_keys[2])) {
	    CBIT_SET(cd->mask, hashed_keys[2]);
	    on_xition_cnt++;
	}
	if (!CBIT_TEST(cd->mask, hashed_keys[3])) {
	    CBIT_SET(cd->mask, hashed_keys[3]);
	    on_xition_cnt++;
	}
	statHistCount(&Counter.cd.on_xition_count, on_xition_cnt);
    }
#endif
    cd->count++;
}

void
cacheDigestDel(CacheDigest * cd, const cache_key * key)
{
    assert(cd && key);
    cd->del_count++;
    /* we do not support deletions from the digest */
}

/* returns mask utilization parameters */
static void
cacheDigestStats(const CacheDigest * cd, CacheDigestStats * stats)
{
    int on_count = 0;
    int pos = cd->mask_size * 8;
    int seq_len_sum = 0;
    int seq_count = 0;
    int cur_seq_len = 0;
    int cur_seq_type = 1;
    assert(stats);
    memset(stats, 0, sizeof(*stats));
    while (pos-- > 0) {
	const int is_on = CBIT_TEST(cd->mask, pos);
	if (is_on)
	    on_count++;
	if (is_on != cur_seq_type || !pos) {
	    seq_len_sum += cur_seq_len;
	    seq_count++;
	    cur_seq_type = !cur_seq_type;
	    cur_seq_len = 0;
	}
	cur_seq_len++;
    }
    stats->bit_count = cd->mask_size * 8;
    stats->bit_on_count = on_count;
    stats->bseq_len_sum = seq_len_sum;
    stats->bseq_count = seq_count;
}

void
cacheDigestGuessStatsUpdate(cd_guess_stats *stats, int real_hit, int guess_hit)
{
    assert(stats);
    if (real_hit) {
	if (guess_hit)
	    stats->true_hits++;
	else
	    stats->false_misses++;
    } else {
	if (guess_hit)
	    stats->false_hits++;
	else
	    stats->true_misses++;
    }
}

void
cacheDigestGuessStatsReport(const cd_guess_stats *stats, StoreEntry * sentry, const char *label)
{
    const int true_count = stats->true_hits + stats->true_misses;
    const int false_count = stats->false_hits + stats->false_misses;
    const int hit_count = stats->true_hits + stats->false_hits;
    const int miss_count = stats->true_misses + stats->false_misses;
    const int tot_count = true_count + false_count;
    
    assert(label);
    assert(tot_count == hit_count + miss_count); /* paranoid */

    storeAppendPrintf(sentry, "Digest guesses stats for %s:\n", label);
    storeAppendPrintf(sentry, "guess\t hit\t\t miss\t\t total\t\t\n");
    storeAppendPrintf(sentry, " \t #\t %%\t #\t %%\t #\t %%\t\n");

    storeAppendPrintf(sentry, "true\t %d\t %.2f\t %d\t %.2f\t %d\t %.2f\n",
	stats->true_hits, xpercent(stats->true_hits, tot_count),
	stats->true_misses, xpercent(stats->true_misses, tot_count),
	true_count, xpercent(true_count, tot_count));
    storeAppendPrintf(sentry, "false\t %d\t %.2f\t %d\t %.2f\t %d\t %.2f\n",
	stats->false_hits, xpercent(stats->false_hits, tot_count),
	stats->false_misses, xpercent(stats->false_misses, tot_count),
	false_count, xpercent(false_count, tot_count));
    storeAppendPrintf(sentry, "all\t %d\t %.2f\t %d\t %.2f\t %d\t %.2f\n",
	hit_count, xpercent(hit_count, tot_count),
	miss_count, xpercent(miss_count, tot_count),
	tot_count, xpercent(tot_count, tot_count));
}

void
cacheDigestReport(CacheDigest *cd, const char *label, StoreEntry * e)
{
    CacheDigestStats stats;
    assert(cd && e);
    cacheDigestStats(cd, &stats);
    storeAppendPrintf(e, "%s digest: size: %d bytes\n",
	label ? label : "", stats.bit_count / 8
	);
    storeAppendPrintf(e, "\t entries: count: %d capacity: %d util: %d%%\n",
	cd->count,
	cd->capacity,
	xpercentInt(cd->count, cd->capacity)
	);
    storeAppendPrintf(e, "\t deletion attempts: %d\n",
	cd->del_count
	);
    storeAppendPrintf(e, "\t bits: on: %d capacity: %d util: %d%%\n",
	stats.bit_on_count, stats.bit_count,
	xpercentInt(stats.bit_on_count, stats.bit_count)
	);
    storeAppendPrintf(e, "\t bit-seq: count: %d avg.len: %.2f\n",
	stats.bseq_count,
	xdiv(stats.bseq_len_sum, stats.bseq_count)
	);
}

static size_t
cacheDigestCalcMaskSize(int cap)
{
    return (size_t) (cap * BitsPerEntry + 7) / 8;
}

static void
cacheDigestHashKey(const CacheDigest *cd, const cache_key *key)
{
    const int bit_count = cd->mask_size * 8;
    /* get four hashed values */
    memcpy(hashed_keys, key, sizeof(hashed_keys));
    /* wrap */
    hashed_keys[0] %= bit_count;
    hashed_keys[1] %= bit_count;
    hashed_keys[2] %= bit_count;
    hashed_keys[3] %= bit_count;

    debug(70,9) ("cacheDigestHashKey: %s -(%d)-> %d %d %d %d\n",
	storeKeyText(key), bit_count, hashed_keys[0], hashed_keys[1], hashed_keys[2], hashed_keys[3]);
}
