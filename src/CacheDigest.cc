/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 70    Cache Digest */

#include "squid.h"
#include "md5.h"
#include "StatCounters.h"
#include "Store.h"
#include "store_key_md5.h"

#if USE_CACHE_DIGESTS

#include "CacheDigest.h"
#include "util.h"

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

void
CacheDigest::init(uint64_t newCapacity)
{
    const auto newMaskSz = CacheDigest::CalcMaskSize(newCapacity, bits_per_entry);
    assert(newCapacity > 0 && bits_per_entry > 0);
    assert(newMaskSz != 0);
    capacity = newCapacity;
    mask_size = newMaskSz;
    mask = static_cast<char *>(xcalloc(mask_size,1));
    debugs(70, 2, "capacity: " << capacity << " entries, bpe: " << bits_per_entry << "; size: "
           << mask_size << " bytes");
}

CacheDigest::CacheDigest(uint64_t aCapacity, uint8_t bpe) :
    count(0),
    del_count(0),
    capacity(0),
    mask(nullptr),
    mask_size(0),
    bits_per_entry(bpe)
{
    assert(SQUID_MD5_DIGEST_LENGTH == 16);  /* our hash functions rely on 16 byte keys */
    updateCapacity(aCapacity);
}

CacheDigest::~CacheDigest()
{
    xfree(mask);
}

CacheDigest *
CacheDigest::clone() const
{
    CacheDigest *cl = new CacheDigest(capacity, bits_per_entry);
    cl->count = count;
    cl->del_count = del_count;
    assert(mask_size == cl->mask_size);
    memcpy(cl->mask, mask, mask_size);
    return cl;
}

void
CacheDigest::clear()
{
    count = del_count = 0;
    memset(mask, 0, mask_size);
}

void
CacheDigest::updateCapacity(uint64_t newCapacity)
{
    safe_free(mask);
    init(newCapacity); // will re-init mask and mask_size
}

bool
CacheDigest::contains(const cache_key * key) const
{
    assert(key);
    /* hash */
    cacheDigestHashKey(this, key);
    /* test corresponding bits */
    return
        CBIT_TEST(mask, hashed_keys[0]) &&
        CBIT_TEST(mask, hashed_keys[1]) &&
        CBIT_TEST(mask, hashed_keys[2]) &&
        CBIT_TEST(mask, hashed_keys[3]);
}

void
CacheDigest::add(const cache_key * key)
{
    assert(key);
    /* hash */
    cacheDigestHashKey(this, key);
    /* turn on corresponding bits */
    int on_xition_cnt = 0;

    if (!CBIT_TEST(mask, hashed_keys[0])) {
        CBIT_SET(mask, hashed_keys[0]);
        ++on_xition_cnt;
    }

    if (!CBIT_TEST(mask, hashed_keys[1])) {
        CBIT_SET(mask, hashed_keys[1]);
        ++on_xition_cnt;
    }

    if (!CBIT_TEST(mask, hashed_keys[2])) {
        CBIT_SET(mask, hashed_keys[2]);
        ++on_xition_cnt;
    }

    if (!CBIT_TEST(mask, hashed_keys[3])) {
        CBIT_SET(mask, hashed_keys[3]);
        ++on_xition_cnt;
    }

    statCounter.cd.on_xition_count.count(on_xition_cnt);
    ++count;
}

void
CacheDigest::remove(const cache_key * key)
{
    assert(key);
    ++del_count;
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

double
CacheDigest::usedMaskPercent() const
{
    CacheDigestStats stats;
    cacheDigestStats(this, &stats);
    return xpercent(stats.bit_on_count, stats.bit_count);
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
cacheDigestGuessStatsReport(const CacheDigestGuessStats * stats, StoreEntry * sentry, const SBuf &label)
{
    const int true_count = stats->trueHits + stats->trueMisses;
    const int false_count = stats->falseHits + stats->falseMisses;
    const int hit_count = stats->trueHits + stats->falseHits;
    const int miss_count = stats->trueMisses + stats->falseMisses;
    const int tot_count = true_count + false_count;

    assert(!label.isEmpty());
    assert(tot_count == hit_count + miss_count);    /* paranoid */

    if (!tot_count) {
        storeAppendPrintf(sentry, "no guess stats for " SQUIDSBUFPH " available\n", SQUIDSBUFPRINT(label));
        return;
    }

    storeAppendPrintf(sentry, "Digest guesses stats for " SQUIDSBUFPH ":\n", SQUIDSBUFPRINT(label));
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
}

void
cacheDigestReport(CacheDigest * cd, const SBuf &label, StoreEntry * e)
{
    CacheDigestStats stats;
    assert(cd && e);
    cacheDigestStats(cd, &stats);
    storeAppendPrintf(e, SQUIDSBUFPH " digest: size: %d bytes\n",
                      SQUIDSBUFPRINT(label), stats.bit_count / 8
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

/// CacheDigest::CalcMaskSize() helper to compute digest mask size without
/// accounting for any limits or restrictions other than those imposed by
/// uint64_t type/math itself.
static uint64_t
UnsafeMaskSize(const uint64_t cap, const uint8_t bpe)
{
    Assure(bpe);

    // This limit is paranoid because no instance can store enough objects to
    // exceed this maximum.
    const auto maxMaskSize = std::numeric_limits<uint64_t>::max() / 8;

    // Same as ((cap*bpe + 7)/8 > maxMaskSize) but without overflowing multiplication or sum
    if (cap > (maxMaskSize*8 - 7)/bpe)
        return maxMaskSize;

    return (cap*bpe + 7)/8;
}

uint32_t
CacheDigest::CalcMaskSize(uint64_t cap, uint8_t bpe)
{
    // Our mask_size data member is uint32_t. That type is hard-coded in several
    // places. TODO: Use a unique type name while revising related types. We
    // cannot simply cap calculations at the maximum uint32_t value because we
    // must also satisfy the following requirements to protect mask_size users:
    //
    // R1. Avoid overflows in code that does `mask_size * 8` (e.g., to compute bit positions).
    // R2. Avoid overflows in code that stores `mask_size * 8` as `int`.
    // R3. Avoid overflows in legacy callers that cast `mask_size` to `ssize_t`.
    // R4. Avoid unreasonably large memory allocations for mask storage.
    //     Bug 4534 fix defined 256MB allocations as "reasonable".
    // R5. Ensure that the digest capacity derived from this mask size can be
    //     sent to legacy installations that assert that the corresponding mask
    //     bit count is less than INT_MAX.
    //
    // Some of the current limits below are mathematically redundant (e.g., R5
    // satisfies R2), but are explicitly listed to assist with safe refactoring.
    //
    // For a typical 32-bit `int`, this maxMaskSize is 268'435'454 bytes.
    const auto maxMaskSize = std::min({
        static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) / 8, // R1
        static_cast<uint64_t>(std::numeric_limits<int>::max()) / 8, // R2
        static_cast<uint64_t>(std::numeric_limits<ssize_t>::max()), // R3
        static_cast<uint64_t>(256)*1024*1024, // R4
        static_cast<uint64_t>(INT_MAX - 8) / 8}); // R5

    const auto rawMaskSize = ::UnsafeMaskSize(cap, bpe);
    return static_cast<uint32_t>(std::min(rawMaskSize, maxMaskSize));
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

