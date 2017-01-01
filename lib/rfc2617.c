/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* The source in this file is derived from the reference implementation
 * in RFC 2617.
 * RFC 2617 is Copyright (C) The Internet Society (1999).  All Rights Reserved.
 *
 * The Squid copyright and licence statement covers all changes made to the
 * reference implementation.
 *
 * Key changes were: alteration to a plain C layout.
 * Create CvtBin function
 * Allow CalcHA1 to make use of precaculated username:password:realm hash's
 * to prevent squid knowing the users password (idea suggested in RFC 2617).
 */

#include "squid.h"
#include <string.h>
#include "md5.h"
#include "rfc2617.h"

void
CvtHex(const HASH Bin, HASHHEX Hex)
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHLEN; i++) {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
            Hex[i * 2] = (j + '0');
        else
            Hex[i * 2] = (j + 'a' - 10);
        j = Bin[i] & 0xf;
        if (j <= 9)
            Hex[i * 2 + 1] = (j + '0');
        else
            Hex[i * 2 + 1] = (j + 'a' - 10);
    }
    Hex[HASHHEXLEN] = '\0';
}

void
CvtBin(const HASHHEX Hex, HASH Bin)
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHHEXLEN; i++) {
        unsigned char n;
        j = Hex[i];
        if (('0' <= j) && (j <= '9'))
            n = j - '0';
        else if (('a' <= j) && (j <= 'f'))
            n = j - 'a' + 10;
        else if (('A' <= j) && (j <= 'F'))
            n = j - 'A' + 10;
        else
            continue;
        if (i % 2 == 0)
            Bin[i / 2] = n << 4;
        else
            Bin[i / 2] |= n;
    }
    /* FIXME: Coverity detects the below as dead code.
      Why? :: right here i == 32
        which means the first step of the for loop makes i==16
        and cannot be < HASHLEN (which is also 16)
    */
    for (i = i / 2; i < HASHLEN; i++) {
        Bin[i] = '\0';
    }
}

/* calculate H(A1) as per spec */
void
DigestCalcHA1(
    const char *pszAlg,
    const char *pszUserName,
    const char *pszRealm,
    const char *pszPassword,
    const char *pszNonce,
    const char *pszCNonce,
    HASH HA1,
    HASHHEX SessionKey
)
{
    SquidMD5_CTX Md5Ctx;

    if (pszUserName) {
        SquidMD5Init(&Md5Ctx);
        SquidMD5Update(&Md5Ctx, pszUserName, strlen(pszUserName));
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, pszRealm, strlen(pszRealm));
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, pszPassword, strlen(pszPassword));
        SquidMD5Final((unsigned char *) HA1, &Md5Ctx);
    }
    if (strcasecmp(pszAlg, "md5-sess") == 0) {
        HASHHEX HA1Hex;
        CvtHex(HA1, HA1Hex);    /* RFC2617 errata */
        SquidMD5Init(&Md5Ctx);
        SquidMD5Update(&Md5Ctx, HA1Hex, HASHHEXLEN);
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, pszNonce, strlen(pszNonce));
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
        SquidMD5Final((unsigned char *) HA1, &Md5Ctx);
    }
    CvtHex(HA1, SessionKey);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void
DigestCalcResponse(
    const HASHHEX HA1,      /* H(A1) */
    const char *pszNonce,   /* nonce from server */
    const char *pszNonceCount,  /* 8 hex digits */
    const char *pszCNonce,  /* client nonce */
    const char *pszQop,     /* qop-value: "", "auth", "auth-int" */
    const char *pszMethod,  /* method from the request */
    const char *pszDigestUri,   /* requested URL */
    const HASHHEX HEntity,  /* H(entity body) if qop="auth-int" */
    HASHHEX Response        /* request-digest or response-digest */
)
{
    SquidMD5_CTX Md5Ctx;
    HASH HA2;
    HASH RespHash;
    HASHHEX HA2Hex;

    /*  calculate H(A2)
     */
    SquidMD5Init(&Md5Ctx);
    SquidMD5Update(&Md5Ctx, pszMethod, strlen(pszMethod));
    SquidMD5Update(&Md5Ctx, ":", 1);
    SquidMD5Update(&Md5Ctx, pszDigestUri, strlen(pszDigestUri));
    if (pszQop && strcasecmp(pszQop, "auth-int") == 0) {
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, HEntity, HASHHEXLEN);
    }
    SquidMD5Final((unsigned char *) HA2, &Md5Ctx);
    CvtHex(HA2, HA2Hex);

    /* calculate response
     */
    SquidMD5Init(&Md5Ctx);
    SquidMD5Update(&Md5Ctx, HA1, HASHHEXLEN);
    SquidMD5Update(&Md5Ctx, ":", 1);
    SquidMD5Update(&Md5Ctx, pszNonce, strlen(pszNonce));
    SquidMD5Update(&Md5Ctx, ":", 1);
    if (pszQop) {
        SquidMD5Update(&Md5Ctx, pszNonceCount, strlen(pszNonceCount));
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, pszCNonce, strlen(pszCNonce));
        SquidMD5Update(&Md5Ctx, ":", 1);
        SquidMD5Update(&Md5Ctx, pszQop, strlen(pszQop));
        SquidMD5Update(&Md5Ctx, ":", 1);
    }
    SquidMD5Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
    SquidMD5Final((unsigned char *) RespHash, &Md5Ctx);
    CvtHex(RespHash, Response);
}

