#ifndef SQUID_CACHEDIGEST_H_
#define SQUID_CACHEDIGEST_H_
/*
 * DEBUG: section 70    Cache Digest
 * AUTHOR: Alex Rousskov
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
