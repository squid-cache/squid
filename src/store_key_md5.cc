
/*
 * DEBUG: section 20    Storage Manager MD5 Cache Keys
 * AUTHOR: Duane Wessels
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

#include "squid.h"
#include "HttpRequest.h"
#include "md5.h"
#include "Mem.h"
#include "store_key_md5.h"
#include "URL.h"

static cache_key null_key[SQUID_MD5_DIGEST_LENGTH];

const char *
storeKeyText(const cache_key *key)
{
    static char buf[SQUID_MD5_DIGEST_LENGTH * 2+1];
    int i;

    for (i = 0; i < SQUID_MD5_DIGEST_LENGTH; ++i)
        snprintf(&buf[i*2],sizeof(buf) - i*2, "%02X", *(key + i));

    return buf;
}

const cache_key *
storeKeyScan(const char *buf)
{
    static unsigned char digest[SQUID_MD5_DIGEST_LENGTH];
    int i;
    int j = 0;
    char t[3];

    for (i = 0; i < SQUID_MD5_DIGEST_LENGTH; ++i) {
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
    const unsigned char *A = (const unsigned char *)a;
    const unsigned char *B = (const unsigned char *)b;
    int i;

    for (i = 0; i < SQUID_MD5_DIGEST_LENGTH; ++i) {
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
    const unsigned char *digest = (const unsigned char *)key;
    unsigned int i = digest[0]
                     | digest[1] << 8
                     | digest[2] << 16
                     | digest[3] << 24;
    return (i & (--n));
}

const cache_key *
storeKeyPrivate(const char *url, const HttpRequestMethod& method, int id)
{
    static cache_key digest[SQUID_MD5_DIGEST_LENGTH];
    SquidMD5_CTX M;
    assert(id > 0);
    debugs(20, 3, "storeKeyPrivate: " << RequestMethodStr(method) << " " << url);
    SquidMD5Init(&M);
    SquidMD5Update(&M, (unsigned char *) &id, sizeof(id));
    SquidMD5Update(&M, (unsigned char *) &method, sizeof(method));
    SquidMD5Update(&M, (unsigned char *) url, strlen(url));
    SquidMD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublic(const char *url, const HttpRequestMethod& method)
{
    static cache_key digest[SQUID_MD5_DIGEST_LENGTH];
    unsigned char m = (unsigned char) method.id();
    SquidMD5_CTX M;
    SquidMD5Init(&M);
    SquidMD5Update(&M, &m, sizeof(m));
    SquidMD5Update(&M, (unsigned char *) url, strlen(url));
    SquidMD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublicByRequest(HttpRequest * request)
{
    return storeKeyPublicByRequestMethod(request, request->method);
}

const cache_key *
storeKeyPublicByRequestMethod(HttpRequest * request, const HttpRequestMethod& method)
{
    static cache_key digest[SQUID_MD5_DIGEST_LENGTH];
    unsigned char m = (unsigned char) method.id();
    const char *url = urlCanonical(request);
    SquidMD5_CTX M;
    SquidMD5Init(&M);
    SquidMD5Update(&M, &m, sizeof(m));
    SquidMD5Update(&M, (unsigned char *) url, strlen(url));

    if (request->vary_headers)
        SquidMD5Update(&M, (unsigned char *) request->vary_headers, strlen(request->vary_headers));

    SquidMD5Final(digest, &M);

    return digest;
}

cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = (cache_key *)memAllocate(MEM_MD5_DIGEST);
    memcpy(dup, key, SQUID_MD5_DIGEST_LENGTH);
    return dup;
}

cache_key *
storeKeyCopy(cache_key * dst, const cache_key * src)
{
    memcpy(dst, src, SQUID_MD5_DIGEST_LENGTH);
    return dst;
}

void
storeKeyFree(const cache_key * key)
{
    memFree((void *) key, MEM_MD5_DIGEST);
}

int
storeKeyHashBuckets(int nbuckets)
{
    int n = 0x2000;

    while (n < nbuckets)
        n <<= 1;

    return n;
}

int
storeKeyNull(const cache_key * key)
{
    if (memcmp(key, null_key, SQUID_MD5_DIGEST_LENGTH) == 0)
        return 1;
    else
        return 0;
}

void
storeKeyInit(void)
{
    memset(null_key, '\0', SQUID_MD5_DIGEST_LENGTH);
}
