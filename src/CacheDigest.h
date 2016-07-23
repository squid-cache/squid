/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 70    Cache Digest */

#ifndef SQUID_CACHEDIGEST_H_
#define SQUID_CACHEDIGEST_H_

/* for cache_key */
#include "typedefs.h"

class CacheDigestGuessStats;
class StoreEntry;

// currently a POD
class CacheDigest
{
public:
    /* public, read-only */
    uint64_t count;          /* number of digested entries */
    uint64_t del_count;      /* number of deletions performed so far */
    uint64_t capacity;       /* expected maximum for .count, not a hard limit */
    char *mask;              /* bit mask */
    uint32_t mask_size;      /* mask size in bytes */
    int8_t bits_per_entry;   /* number of bits allocated for each entry from capacity */
};

CacheDigest *cacheDigestCreate(uint64_t capacity, uint8_t bpe);
void cacheDigestDestroy(CacheDigest * cd);
CacheDigest *cacheDigestClone(const CacheDigest * cd);
void cacheDigestClear(CacheDigest * cd);
void cacheDigestChangeCap(CacheDigest * cd, uint64_t new_cap);
int cacheDigestTest(const CacheDigest * cd, const cache_key * key);
void cacheDigestAdd(CacheDigest * cd, const cache_key * key);
void cacheDigestDel(CacheDigest * cd, const cache_key * key);
uint32_t cacheDigestCalcMaskSize(uint64_t cap, uint8_t bpe);
int cacheDigestBitUtil(const CacheDigest * cd);
void cacheDigestGuessStatsUpdate(CacheDigestGuessStats * stats, int real_hit, int guess_hit);
void cacheDigestGuessStatsReport(const CacheDigestGuessStats * stats, StoreEntry * sentry, const char *label);
void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

#endif /* SQUID_CACHEDIGEST_H_ */

