
/*
 * $Id: store_key_md5.cc,v 1.33 2006/06/21 22:36:08 wessels Exp $
 *
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

static cache_key null_key[MD5_DIGEST_CHARS];

const char *
storeKeyText(const unsigned char *key)
{
    static char buf[MD5_DIGEST_CHARS * 2+1];
    int i;

    for (i = 0; i < MD5_DIGEST_CHARS; i++)
        snprintf(&buf[i*2],sizeof(buf) - i*2, "%02X", *(key + i));

    return buf;
}

const cache_key *
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
    const unsigned char *A = (const unsigned char *)a;
    const unsigned char *B = (const unsigned char *)b;
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
    const unsigned char *digest = (const unsigned char *)key;
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
    debugs(20, 3, "storeKeyPrivate: " << RequestMethodStr[method] << " " << url);
    MD5Init(&M);
    MD5Update(&M, (unsigned char *) &id, sizeof(id));
    MD5Update(&M, (unsigned char *) &method, sizeof(method));
    MD5Update(&M, (unsigned char *) url, strlen(url));
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublic(const char *url, const method_t method)
{
    static cache_key digest[MD5_DIGEST_CHARS];
    unsigned char m = (unsigned char) method;
    MD5_CTX M;
    MD5Init(&M);
    MD5Update(&M, &m, sizeof(m));
    MD5Update(&M, (unsigned char *) url, strlen(url));
    MD5Final(digest, &M);
    return digest;
}

const cache_key *
storeKeyPublicByRequest(HttpRequest * request)
{
    return storeKeyPublicByRequestMethod(request, request->method);
}

const cache_key *
storeKeyPublicByRequestMethod(HttpRequest * request, const method_t method)
{
    static cache_key digest[MD5_DIGEST_CHARS];
    unsigned char m = (unsigned char) method;
    const char *url = urlCanonical(request);
    MD5_CTX M;
    MD5Init(&M);
    MD5Update(&M, &m, sizeof(m));
    MD5Update(&M, (unsigned char *) url, strlen(url));

    if (request->vary_headers)
        MD5Update(&M, (unsigned char *) request->vary_headers, strlen(request->vary_headers));

    MD5Final(digest, &M);

    return digest;
}

cache_key *
storeKeyDup(const cache_key * key)
{
    cache_key *dup = (cache_key *)memAllocate(MEM_MD5_DIGEST);
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
