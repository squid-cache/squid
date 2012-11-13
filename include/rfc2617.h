/* The source in this file is derived from the reference implementation
 * in RFC 2617.
 * RFC 2617 is Copyright (C) The Internet Society (1999).  All Rights Reserved.
 *
 * The following copyright and licence statement covers all changes made to the
 * reference implementation.
 *
 * Key changes to the reference implementation were:
 * alteration to a plain C layout.
 * Create CvtBin function
 * Allow CalcHA1 to make use of precaculated username:password:realm hash's
 * to prevent squid knowing the users password (idea suggested in RFC 2617).
 */

/*
 * DEBUG:
 * AUTHOR: RFC 2617 & Robert Collins
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
#ifndef SQUID_RFC2617_H
#define SQUID_RFC2617_H

#ifdef __cplusplus
extern "C" {
#endif

#define HASHLEN 16
    typedef char HASH[HASHLEN];
#define HASHHEXLEN 32
    typedef char HASHHEX[HASHHEXLEN + 1];

    /* calculate H(A1) as per HTTP Digest spec */
    extern void DigestCalcHA1(
        const char *pszAlg,
        const char *pszUserName,
        const char *pszRealm,
        const char *pszPassword,
        const char *pszNonce,
        const char *pszCNonce,
        HASH HA1,
        HASHHEX SessionKey
    );

    /* calculate request-digest/response-digest as per HTTP Digest spec */
    extern void DigestCalcResponse(
        const HASHHEX HA1,		/* H(A1) */
        const char *pszNonce,	/* nonce from server */
        const char *pszNonceCount,	/* 8 hex digits */
        const char *pszCNonce,	/* client nonce */
        const char *pszQop,		/* qop-value: "", "auth", "auth-int" */
        const char *pszMethod,	/* method from the request */
        const char *pszDigestUri,	/* requested URL */
        const HASHHEX HEntity,	/* H(entity body) if qop="auth-int" */
        HASHHEX Response		/* request-digest or response-digest */
    );

    extern void CvtHex(const HASH Bin, HASHHEX Hex);

    extern void CvtBin(const HASHHEX Hex, HASH Bin);

#ifdef __cplusplus
}
#endif
#endif /* SQUID_RFC2617_H */
