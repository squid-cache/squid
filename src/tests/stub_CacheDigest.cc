/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "typedefs.h" /* for cache_key */

#define STUB_API "CacheDigest.cc"
#include "tests/STUB.h"

class CacheDigest;
class CacheDigestGuessStats;
class StoreEntry;

CacheDigest * cacheDigestCreate(int, int) STUB_RETVAL(NULL)
void cacheDigestDestroy(CacheDigest *) STUB
CacheDigest * cacheDigestClone(const CacheDigest *) STUB_RETVAL(NULL)
void cacheDigestClear(CacheDigest * ) STUB
void cacheDigestChangeCap(CacheDigest *,int) STUB
int cacheDigestTest(const CacheDigest *, const cache_key *) STUB_RETVAL(1)
void cacheDigestAdd(CacheDigest *, const cache_key *) STUB
void cacheDigestDel(CacheDigest *, const cache_key *) STUB
int cacheDigestBitUtil(const CacheDigest *) STUB_RETVAL(0)
void cacheDigestGuessStatsUpdate(CacheDigestGuessStats *, int, int) STUB
void cacheDigestGuessStatsReport(const CacheDigestGuessStats *, StoreEntry *, const char *) STUB
void cacheDigestReport(CacheDigest *, const char *, StoreEntry *) STUB
size_t cacheDigestCalcMaskSize(int, int) STUB_RETVAL(1)

