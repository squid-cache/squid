
/*
 * $Id: store_key_md5.cc,v 1.16 1998/09/15 19:38:02 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager MD5 Cache Keys
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

#include "squid.h"

static cache_key null_key[MD5_DIGEST_CHARS];

const char *
storeKeyText(const unsigned char *key)
{
    static MemBuf mb = MemBufNULL;
    int i;
    memBufReset(&mb);
    for (i = 0; i < MD5_DIGEST_CHARS; i++)
	memBufPrintf(&mb, "%02X", *(key + i));
    return mb.buf;
}

const unsigned char *
storeKeyScan(const char *buf)
{
    static unsigned char digest[MD5_DIGEST_CHARS];
    int i;
    int j = 0;
    char t[3];
    for (i = 0; i < MD5_DIGEST_CHARS; i++) {
	t[0] = *(buf + (j++));
	t[1] = *(buf + (j++));
	t[2] = '\0';
	*(digest + i) = (unsigned char) strtol(t, NULL, 16);
    }
    return digest;
}

int
storeKeyHashCmp(const void *a, const void *b)
{
    const unsigned char *A = a;
    const unsigned char *B = b;
    int i;
    for (i = 0; i < MD5_DIGEST_CHARS; i++) {
	if (A[i] < B[i])
	    return -1;
	if (A[i] > B[i])
	    return 1;
    }
    return 0;
}

unsigned int
storeKeyHashHash(const void *key, unsigned int n)
{
    /* note, n must be a power of 2! */
    const unsigned char *digest = key;
    unsigned int i = digest[0]
    | digest[1] << 8
    | digest[2] << 16
    | digest[3] << 24;
    return (i & (--n));
}

const cache_key *
storeKeyPrivate(const char *url, method_t method, int id)
{
    static cache_key digest[MD5_DIGEST_CHARS];
    MD5_CTX M;
    assert(id > 0);
    debug(20, 3) ("storeKeyPrivate: %s %s\n",
	RequestMethodStr[method], url);
    MD5Init(&M);
    MD5Update(&M, (unsigned char *) &id, sizeof(id));
    MD5Update(&M, (unsigned char *) &method, sizeof(method));
    MD5Update(&M, (unsigned char *) url, strlen(url));
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublic(const char *url, method_t method)
{
    static cache_key digest[MD5_DIGEST_CHARS];
    MD5_CTX M;
    MD5Init(&M);
    MD5Update(&M, (unsigned char *) &method, sizeof(method));
    MD5Update(&M, (unsigned char *) url, strlen(url));
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = memAllocate(MEM_MD5_DIGEST);
    xmemcpy(dup, key, MD5_DIGEST_CHARS);
    return dup;
}

cache_key *
storeKeyCopy(cache_key * dst, const cache_key * src)
{
    xmemcpy(dst, src, MD5_DIGEST_CHARS);
    return dst;
}

void
storeKeyFree(const cache_key * key)
{
    memFree(MEM_MD5_DIGEST, (void *) key);
}

int
storeKeyHashBuckets(int nobj)
{
    if (nobj < 0x2000)
	return 0x2000;
    if (nobj < 0x4000)
	return 0x4000;
    if (nobj < 0x8000)
	return 0x8000;
    return 0x10000;
}

int
storeKeyNull(const cache_key * key)
{
    if (memcmp(key, null_key, MD5_DIGEST_CHARS) == 0)
	return 1;
    else
	return 0;
}

void
storeKeyInit(void)
{
    memset(null_key, '\0', MD5_DIGEST_CHARS);
}
