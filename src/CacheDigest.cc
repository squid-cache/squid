
/*
 * $Id: CacheDigest.cc,v 1.7 1998/04/02 17:11:20 rousskov Exp $
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

static const int BitsPerEntry = 4;

/* static array used by cacheDigestHashKey for optimization purposes */
static u_num32 hashed_keys[4];

/* local functions */
static void cacheDigestHashKey(int bit_count, const char *key);


CacheDigest *
cacheDigestCreate(int capacity)
{
    CacheDigest *cd = xcalloc(1, sizeof(CacheDigest));
    assert(MD5_DIGEST_CHARS == 16);	/* our hash functions rely on 16 byte keys */
    assert(capacity > 0);
    cd->capacity = capacity;
    cd->mask_size = (size_t) (capacity * BitsPerEntry + 7) / 8;
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

/* returns true if the key belongs to the digest */
int
cacheDigestTest(const CacheDigest * cd, const cache_key * key)
{
    assert(cd && key);
    /* hash */
    cacheDigestHashKey(cd->capacity * BitsPerEntry, key);
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
    cacheDigestHashKey(cd->capacity * BitsPerEntry, key);
    /* turn on corresponding bits */
    CBIT_SET(cd->mask, hashed_keys[0]);
    CBIT_SET(cd->mask, hashed_keys[1]);
    CBIT_SET(cd->mask, hashed_keys[2]);
    CBIT_SET(cd->mask, hashed_keys[3]);
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
double
cacheDigestUtil(const CacheDigest * cd, int *bit_cnt_p, int *on_cnt_p)
{
    const int bit_count = cd->capacity * BitsPerEntry;
    int pos = bit_count;
    int on_count = 0;
    while (pos-- > 0) {
	if (CBIT_TEST(cd->mask, pos))
	    on_count++;
    }
    if (bit_cnt_p)
	*bit_cnt_p = bit_count;
    if (on_cnt_p)
	*on_cnt_p = on_count;
    return xpercent(on_count, bit_count);
}

void
cacheDigestReport(CacheDigest *cd, const char *label, StoreEntry * e)
{
    int bit_count, on_count;
    assert(cd && e);
    cacheDigestUtil(cd, &bit_count, &on_count);
    storeAppendPrintf(e, "%s digest: size: %d bytes.\n",
	label ? label : "",
	bit_count/8
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
	on_count, bit_count,
	xpercentInt(on_count, bit_count)
    );
}

static void
cacheDigestHashKey(int bit_count, const char *key)
{
    /* get four hashed values */
    memcpy(hashed_keys, key, sizeof(hashed_keys));
    /* wrap */
    hashed_keys[0] %= bit_count;
    hashed_keys[1] %= bit_count;
    hashed_keys[2] %= bit_count;
    hashed_keys[3] %= bit_count;
}
