#ifndef SQUID_MD5_H
#define SQUID_MD5_H

#if USE_OPENSSL

/*
 * If Squid is compiled with OpenSSL then we use the MD5 routines
 * from there via some wrapper macros, and the rest of this file is ignored..
 */

#if HAVE_OPENSSL_MD5_H
#include <openssl/md5.h>
#else
#error Cannot find OpenSSL headers
#endif

/* Hack to adopt Squid to the OpenSSL syntax */
#define MD5_DIGEST_CHARS MD5_DIGEST_LENGTH

#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final

#else /* USE_OPENSSL */

/*
 * This is the header file for the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 *
 * Changed so as no longer to depend on Colin Plumb's `usual.h'
 * header definitions; now uses stuff from dpkg's config.h
 *  - Ian Jackson <ian@chiark.greenend.org.uk>.
 * Still in the public domain.
 *
 * Changed MD5Update to take a void * for easier use and some other
 * minor cleanup. - Henrik Nordstrom <henrik@henriknordstrom.net>.
 * Still in the public domain.
 *
 */

#include "squid_types.h"

typedef struct MD5Context {
    uint32_t buf[4];
    uint32_t bytes[2];
    uint32_t in[16];
} MD5_CTX;

SQUIDCEXTERN void MD5Init(struct MD5Context *context);
SQUIDCEXTERN void MD5Update(struct MD5Context *context, const void *buf, unsigned len);
SQUIDCEXTERN void MD5Final(uint8_t digest[16], struct MD5Context *context);
SQUIDCEXTERN void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

#define MD5_DIGEST_CHARS         16

#endif /* USE_OPENSSL */
#endif /* SQUID_MD5_H */
