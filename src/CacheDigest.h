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

#ifndef SQUID_CACHEDIGEST_H_
#define SQUID_CACHEDIGEST_H_

#include "typedefs.h"
class CacheDigestGuessStats;
class StoreEntry;
class CacheDigest;

extern CacheDigest *cacheDigestCreate(int capacity, int bpe);
extern void cacheDigestDestroy(CacheDigest * cd);
extern CacheDigest *cacheDigestClone(const CacheDigest * cd);
extern void cacheDigestClear(CacheDigest * cd);
extern void cacheDigestChangeCap(CacheDigest * cd, int new_cap);
extern int cacheDigestTest(const CacheDigest * cd, const cache_key * key);
extern void cacheDigestAdd(CacheDigest * cd, const cache_key * key);
extern void cacheDigestDel(CacheDigest * cd, const cache_key * key);
extern size_t cacheDigestCalcMaskSize(int cap, int bpe);
extern int cacheDigestBitUtil(const CacheDigest * cd);
extern void cacheDigestGuessStatsUpdate(CacheDigestGuessStats * stats, int real_hit, int guess_hit);
extern void cacheDigestGuessStatsReport(const CacheDigestGuessStats * stats, StoreEntry * sentry, const char *label);
extern void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

#endif /* SQUID_CACHEDIGEST_H_ */
