/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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
    const HASHHEX HA1,      /* H(A1) */
    const char *pszNonce,   /* nonce from server */
    const char *pszNonceCount,  /* 8 hex digits */
    const char *pszCNonce,  /* client nonce */
    const char *pszQop,     /* qop-value: "", "auth", "auth-int" */
    const char *pszMethod,  /* method from the request */
    const char *pszDigestUri,   /* requested URL */
    const HASHHEX HEntity,  /* H(entity body) if qop="auth-int" */
    HASHHEX Response        /* request-digest or response-digest */
);

extern void CvtHex(const HASH Bin, HASHHEX Hex);

extern void CvtBin(const HASHHEX Hex, HASH Bin);

#ifdef __cplusplus
}
#endif
#endif /* SQUID_RFC2617_H */

