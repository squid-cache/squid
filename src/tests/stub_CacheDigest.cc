/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "store_key_md5.h"

#define STUB_API "CacheDigest.cc"
#include "tests/STUB.h"

class CacheDigest;
class CacheDigestGuessStats;
class StoreEntry;

#include "CacheDigest.h"
CacheDigest::CacheDigest(uint64_t, uint8_t) {STUB}
CacheDigest::~CacheDigest() {STUB}
CacheDigest *CacheDigest::clone() const STUB_RETVAL(nullptr)
void CacheDigest::clear() STUB
void CacheDigest::updateCapacity(uint64_t) STUB
bool CacheDigest::contains(const cache_key *) const STUB_RETVAL(false)
void CacheDigest::add(const cache_key *) STUB
void CacheDigest::remove(const cache_key *) STUB
double CacheDigest::usedMaskPercent() const STUB_RETVAL(0.0)
void cacheDigestGuessStatsUpdate(CacheDigestGuessStats *, int, int) STUB
void cacheDigestGuessStatsReport(const CacheDigestGuessStats *, StoreEntry *, const SBuf &) STUB
void cacheDigestReport(CacheDigest *, const SBuf &, StoreEntry *) STUB
uint32_t CacheDigest::CalcMaskSize(uint64_t, uint8_t) STUB_RETVAL(1)

