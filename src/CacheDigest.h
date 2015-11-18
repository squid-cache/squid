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

#include "mem/forward.h"
#include "store_key_md5.h"

class CacheDigestGuessStats;
class StoreEntry;

class CacheDigest
{
    MEMPROXY_CLASS(CacheDigest);
public:
    CacheDigest(int capacity, int bpe);
    ~CacheDigest();

    // NP: only used by broken unit-test
    /// produce a new identical copy of the digest object
    CacheDigest *clone() const;

    /// reset the digest mask and counters
    void clear();

    /// changes mask size to fit newCapacity, resets bits to 0
    void updateCapacity(int newCapacity);

    void add(const cache_key * key);
    void remove(const cache_key * key);

    /// \returns true if the key belongs to the digest
    bool contains(const cache_key * key) const;

    /// percentage of mask bits which are used
    double usedMaskPercent() const;

    /// calculate the size of mask required to digest up to
    /// a specified capacity and bitsize.
    static size_t CalcMaskSize(int cap, int bpe);

private:
    void init(int newCapacity);

public:
    /* public, read-only */
    char *mask;         /* bit mask */
    int mask_size;      /* mask size in bytes */
    int capacity;       /* expected maximum for .count, not a hard limit */
    int bits_per_entry;     /* number of bits allocated for each entry from capacity */
    int count;          /* number of digested entries */
    int del_count;      /* number of deletions performed so far */
};

void cacheDigestGuessStatsUpdate(CacheDigestGuessStats * stats, int real_hit, int guess_hit);
void cacheDigestGuessStatsReport(const CacheDigestGuessStats * stats, StoreEntry * sentry, const char *label);
void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

#endif /* SQUID_CACHEDIGEST_H_ */

