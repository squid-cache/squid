
/*
 * $Id: CacheDigest.cc,v 1.2 1998/03/31 05:35:35 wessels Exp $
 *
 * DEBUG: section ??    Cache Digest
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
cacheDigestDel(CacheDigest * cd, const cache_key * key)
{
    assert(cd && key);
    cd->del_count++;
    /* we do not support deletions from the digest */
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
