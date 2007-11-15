#ifndef SQUID_MD5_H
#define SQUID_MD5_H

#if USE_OPENSSL && HAVE_OPENSSL_MD5_H

/*
 * If Squid is compiled with OpenSSL then we use the MD5 routines
 * from there via some wrapper macros, and the rest of this file is ignored..
 */
#include <openssl/md5.h>

#define xMD5Init MD5_Init
#define xMD5Update MD5_Update
#define xMD5Final MD5_Final

#elif USE_OPENSSL && !HAVE_OPENSSL_MD5_H
#error Cannot find OpenSSL MD5 headers

#elif HAVE_SYS_MD5_H
/*
 * Solaris 10 provides MD5 as part of the system.
 * So do other OS - but without MD5_DIGEST_LENGTH defined
 * for them we need to still use the bunded version
 */
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <sys/md5.h>

#endif

/* according to CacheDigest.cc squid REQUIRES 16-byte here for hash keys */
#if MD5_DIGEST_LENGTH == 16

  /* We found a nice usable version. No need for ours */
#define USE_SQUID_MD5 0

  /* adopt the supplied version we are able to use. */
#define xMD5Init MD5Init
#define xMD5Update MD5Update
#define xMD5Final MD5Final
#define MD5_DIGEST_CHARS MD5_DIGEST_LENGTH

#else /* NEED squid bundled version */

  /* Turn on internal MD5 code */
#define USE_SQUID_MD5 1

  /* remove MD5_CTX which may have been defined. */
#undef MD5_CTX

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
 * Changed function names to xMD5* to prevent symbol-clashes when
 * external library code actually used.
 * - Amos Jeffries <squid3@treenet.co.nz>
 *
 */

#include "squid_types.h"

typedef struct MD5Context {
    uint32_t buf[4];
    uint32_t bytes[2];
    uint32_t in[16];
} MD5_CTX;

SQUIDCEXTERN void xMD5Init(struct MD5Context *context);
SQUIDCEXTERN void xMD5Update(struct MD5Context *context, const void *buf, unsigned len);
SQUIDCEXTERN void xMD5Final(uint8_t digest[16], struct MD5Context *context);
SQUIDCEXTERN void xMD5Transform(uint32_t buf[4], uint32_t const in[16]);

#endif /* MD5_DIGEST_CHARS != 16 */


#endif /* SQUID_MD5_H */
