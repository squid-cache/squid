/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MD5_H
#define SQUID_MD5_H

#if HAVE_NETTLE_MD5_H
#include <nettle/md5.h>

typedef struct md5_ctx SquidMD5_CTX;

#define SquidMD5Init(c)       md5_init((c))
#define SquidMD5Update(c,b,l) md5_update((c), (l), (const uint8_t *)(b))
#define SquidMD5Final(d,c)    md5_digest((c), MD5_DIGEST_SIZE, (uint8_t *)(d))

#define SQUID_MD5_DIGEST_LENGTH MD5_DIGEST_SIZE

#else
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
 * Prefixed all symbols with "Squid" so they don't collide with
 * other libraries.  Duane Wessels <wessels@squid-cache.org>.
 * Still in the public domain.
 *
 */

typedef struct SquidMD5Context {
    uint32_t buf[4];
    uint32_t bytes[2];
    uint32_t in[16];
} SquidMD5_CTX;

SQUIDCEXTERN void SquidMD5Init(struct SquidMD5Context *context);
SQUIDCEXTERN void SquidMD5Update(struct SquidMD5Context *context, const void *buf, unsigned len);
SQUIDCEXTERN void SquidMD5Final(uint8_t digest[16], struct SquidMD5Context *context);
SQUIDCEXTERN void SquidMD5Transform(uint32_t buf[4], uint32_t const in[16]);

#define SQUID_MD5_DIGEST_LENGTH         16

#endif /* HAVE_NETTLE_MD5_H */

#endif /* SQUID_MD5_H */

