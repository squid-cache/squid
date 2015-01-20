/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
    char *mask;         /* bit mask */
    int mask_size;      /* mask size in bytes */
    int capacity;       /* expected maximum for .count, not a hard limit */
    int bits_per_entry;     /* number of bits allocated for each entry from capacity */
    int count;          /* number of digested entries */
    int del_count;      /* number of deletions performed so far */
};

CacheDigest *cacheDigestCreate(int capacity, int bpe);
void cacheDigestDestroy(CacheDigest * cd);
CacheDigest *cacheDigestClone(const CacheDigest * cd);
void cacheDigestClear(CacheDigest * cd);
void cacheDigestChangeCap(CacheDigest * cd, int new_cap);
int cacheDigestTest(const CacheDigest * cd, const cache_key * key);
void cacheDigestAdd(CacheDigest * cd, const cache_key * key);
void cacheDigestDel(CacheDigest * cd, const cache_key * key);
size_t cacheDigestCalcMaskSize(int cap, int bpe);
int cacheDigestBitUtil(const CacheDigest * cd);
void cacheDigestGuessStatsUpdate(CacheDigestGuessStats * stats, int real_hit, int guess_hit);
void cacheDigestGuessStatsReport(const CacheDigestGuessStats * stats, StoreEntry * sentry, const char *label);
void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

#endif /* SQUID_CACHEDIGEST_H_ */

