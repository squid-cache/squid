/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 70    Cache Digest */

#include "squid.h"
#include "md5.h"
#include "Mem.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_key_md5.h"

#if USE_CACHE_DIGESTS

#include "CacheDigest.h"

/* local types */

typedef struct {
    int bit_count;      /* total number of bits */
    int bit_on_count;       /* #bits turned on */
    int bseq_len_sum;       /* sum of all bit seq length */
    int bseq_count;     /* number of bit seqs */
} CacheDigestStats;

/* local functions */
static void cacheDigestHashKey(const CacheDigest * cd, const cache_key * key);

/* static array used by cacheDigestHashKey for optimization purposes */
static uint32_t hashed_keys[4];

static void
cacheDigestInit(CacheDigest * cd, uint64_t capacity, uint8_t bpe)
{
    const uint32_t mask_size = cacheDigestCalcMaskSize(capacity, bpe);
    assert(cd);
    assert(capacity > 0 && bpe > 0);
    assert(mask_size != 0);
    cd->capacity = capacity;
    cd->bits_per_entry = bpe;
    cd->mask_size = mask_size;
    cd->mask = (char *)xcalloc(cd->mask_size, 1);
    debugs(70, 2, "cacheDigestInit: capacity: " << cd->capacity << " entries, bpe: " << cd->bits_per_entry << "; size: "
           << cd->mask_size << " bytes");
}

CacheDigest *
cacheDigestCreate(uint64_t capacity, uint8_t bpe)
{
    CacheDigest *cd = (CacheDigest *)memAllocate(MEM_CACHE_DIGEST);
    assert(SQUID_MD5_DIGEST_LENGTH == 16);  /* our hash functions rely on 16 byte keys */
    cacheDigestInit(cd, capacity, bpe);
    return cd;
}

static void
cacheDigestClean(CacheDigest * cd)
{
    assert(cd);
    xfree(cd->mask);
    cd->mask = NULL;
}

void
cacheDigestDestroy(CacheDigest * cd)
{
    assert(cd);
    cacheDigestClean(cd);
    memFree(cd, MEM_CACHE_DIGEST);
}

CacheDigest *
cacheDigestClone(const CacheDigest * cd)
{
    CacheDigest *clone;
    assert(cd);
    clone = cacheDigestCreate(cd->capacity, cd->bits_per_entry);
    clone->count = cd->count;
    clone->del_count = cd->del_count;
    assert(cd->mask_size == clone->mask_size);
    memcpy(clone->mask, cd->mask, cd->mask_size);
    return clone;
}

void
cacheDigestClear(CacheDigest * cd)
{
    assert(cd);
    cd->count = cd->del_count = 0;
    memset(cd->mask, 0, cd->mask_size);
}

/* changes mask size, resets bits to 0, preserves "cd" pointer */
void
cacheDigestChangeCap(CacheDigest * cd, uint64_t new_cap)
{
    assert(cd);
    cacheDigestClean(cd);
    cacheDigestInit(cd, new_cap, cd->bits_per_entry);
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
            ++on_xition_cnt;
        }

        if (!CBIT_TEST(cd->mask, hashed_keys[1])) {
            CBIT_SET(cd->mask, hashed_keys[1]);
            ++on_xition_cnt;
        }

        if (!CBIT_TEST(cd->mask, hashed_keys[2])) {
            CBIT_SET(cd->mask, hashed_keys[2]);
            ++on_xition_cnt;
        }

        if (!CBIT_TEST(cd->mask, hashed_keys[3])) {
            CBIT_SET(cd->mask, hashed_keys[3]);
            ++on_xition_cnt;
        }

        statCounter.cd.on_xition_count.count(on_xition_cnt);
    }
#endif
    ++ cd->count;
}

void
cacheDigestDel(CacheDigest * cd, const cache_key * key)
{
    assert(cd && key);
    ++ cd->del_count;
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
        const int is_on = 0 != CBIT_TEST(cd->mask, pos);

        if (is_on)
            ++on_count;

        if (is_on != cur_seq_type || !pos) {
            seq_len_sum += cur_seq_len;
            ++seq_count;
            cur_seq_type = is_on;
            cur_seq_len = 0;
        }

        ++cur_seq_len;
    }

    stats->bit_count = cd->mask_size * 8;
    stats->bit_on_count = on_count;
    stats->bseq_len_sum = seq_len_sum;
    stats->bseq_count = seq_count;
}

int
cacheDigestBitUtil(const CacheDigest * cd)
{
    CacheDigestStats stats;
    assert(cd);
    cacheDigestStats(cd, &stats);
    return xpercentInt(stats.bit_on_count, stats.bit_count);
}

void
cacheDigestGuessStatsUpdate(CacheDigestGuessStats * stats, int real_hit, int guess_hit)
{
    assert(stats);

    if (real_hit) {
        if (guess_hit)
            ++stats->trueHits;
        else
            ++stats->falseMisses;
    } else {
        if (guess_hit)
            ++stats->falseHits;
        else
            ++stats->trueMisses;
    }
}

void
cacheDigestGuessStatsReport(const CacheDigestGuessStats * stats, StoreEntry * sentry, const char *label)
{
    const int true_count = stats->trueHits + stats->trueMisses;
    const int false_count = stats->falseHits + stats->falseMisses;
    const int hit_count = stats->trueHits + stats->falseHits;
    const int miss_count = stats->trueMisses + stats->falseMisses;
    const int tot_count = true_count + false_count;

    assert(label);
    assert(tot_count == hit_count + miss_count);    /* paranoid */

    if (!tot_count) {
        storeAppendPrintf(sentry, "no guess stats for %s available\n", label);
        return;
    }

    storeAppendPrintf(sentry, "Digest guesses stats for %s:\n", label);
    storeAppendPrintf(sentry, "guess\t hit\t\t miss\t\t total\t\t\n");
    storeAppendPrintf(sentry, " \t #\t %%\t #\t %%\t #\t %%\t\n");
    storeAppendPrintf(sentry, "true\t %d\t %.2f\t %d\t %.2f\t %d\t %.2f\n",
                      stats->trueHits, xpercent(stats->trueHits, tot_count),
                      stats->trueMisses, xpercent(stats->trueMisses, tot_count),
                      true_count, xpercent(true_count, tot_count));
    storeAppendPrintf(sentry, "false\t %d\t %.2f\t %d\t %.2f\t %d\t %.2f\n",
                      stats->falseHits, xpercent(stats->falseHits, tot_count),
                      stats->falseMisses, xpercent(stats->falseMisses, tot_count),
                      false_count, xpercent(false_count, tot_count));
    storeAppendPrintf(sentry, "all\t %d\t %.2f\t %d\t %.2f\t %d\t %.2f\n",
                      hit_count, xpercent(hit_count, tot_count),
                      miss_count, xpercent(miss_count, tot_count),
                      tot_count, xpercent(tot_count, tot_count));
    storeAppendPrintf(sentry, "\tclose_hits: %d ( %d%%) /* cd said hit, doc was in the peer cache, but we got a miss */\n",
                      stats->closeHits, xpercentInt(stats->closeHits, stats->falseHits));
}

void
cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e)
{
    CacheDigestStats stats;
    assert(cd && e);
    cacheDigestStats(cd, &stats);
    storeAppendPrintf(e, "%s digest: size: %d bytes\n",
                      label ? label : "", stats.bit_count / 8
                     );
    storeAppendPrintf(e, "\t entries: count: %" PRIu64 " capacity: %" PRIu64 " util: %d%%\n",
                      cd->count,
                      cd->capacity,
                      xpercentInt(cd->count, cd->capacity)
                     );
    storeAppendPrintf(e, "\t deletion attempts: %" PRIu64 "\n",
                      cd->del_count
                     );
    storeAppendPrintf(e, "\t bits: per entry: %d on: %d capacity: %d util: %d%%\n",
                      cd->bits_per_entry,
                      stats.bit_on_count, stats.bit_count,
                      xpercentInt(stats.bit_on_count, stats.bit_count)
                     );
    storeAppendPrintf(e, "\t bit-seq: count: %d avg.len: %.2f\n",
                      stats.bseq_count,
                      xdiv(stats.bseq_len_sum, stats.bseq_count)
                     );
}

uint32_t
cacheDigestCalcMaskSize(uint64_t cap, uint8_t bpe)
{
    uint64_t bitCount = (cap * bpe) + 7;
    assert(bitCount < INT_MAX); // dont 31-bit overflow later
    return static_cast<uint32_t>(bitCount / 8);
}

static void
cacheDigestHashKey(const CacheDigest * cd, const cache_key * key)
{
    const uint32_t bit_count = cd->mask_size * 8;
    unsigned int tmp_keys[4];
    /* we must memcpy to ensure alignment */
    memcpy(tmp_keys, key, sizeof(tmp_keys));
    hashed_keys[0] = htonl(tmp_keys[0]) % bit_count;
    hashed_keys[1] = htonl(tmp_keys[1]) % bit_count;
    hashed_keys[2] = htonl(tmp_keys[2]) % bit_count;
    hashed_keys[3] = htonl(tmp_keys[3]) % bit_count;
    debugs(70, 9, "cacheDigestHashKey: " << storeKeyText(key) << " -(" <<
           bit_count << ")-> " << hashed_keys[0] << " " << hashed_keys[1] <<
           " " << hashed_keys[2] << " " << hashed_keys[3]);
}

#endif

