/*
 * $Id: md5.h,v 1.15 2003/01/23 00:36:47 robertc Exp $
 */

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

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 * 
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 * 
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 * 
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 * 
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#include "config.h"

/* MD5 context. */
typedef struct {
    u_int32_t state[4];		/* state (ABCD) */
    u_int32_t count[2];		/* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];	/* input buffer */
} MD5_CTX;

SQUIDCEXTERN void MD5Init(MD5_CTX *);
SQUIDCEXTERN void MD5Update(MD5_CTX *, const void *, unsigned long);
SQUIDCEXTERN void MD5Final(unsigned char *, MD5_CTX *);

#define MD5_DIGEST_CHARS         16

#endif /* USE_OPENSSL */

#endif /* SQUID_MD5_H */
