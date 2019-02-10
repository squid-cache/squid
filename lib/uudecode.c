/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "uudecode.h"

/* aaaack but it's fast and const should make it shared text page. */
const int pr2six[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

char *
uudecode(const char *bufcoded)
{
    int nbytesdecoded;
    const unsigned char *bufin;
    char *bufplain;
    unsigned char *bufout;
    int nprbytes;

    /* Strip leading whitespace. */

    while (*bufcoded == ' ' || *bufcoded == '\t')
        bufcoded++;

    /* Figure out how many characters are in the input buffer.
     * Allocate this many from the per-transaction pool for the result.
     */
    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (const char *) bufin - bufcoded - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufplain = xmalloc(nbytesdecoded + 1);
    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 0) {
        *(bufout++) =
            (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
        *(bufout++) =
            (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes & 03) {
        if (pr2six[bufin[-2]] > 63)
            nbytesdecoded -= 2;
        else
            nbytesdecoded -= 1;
    }
    bufplain[nbytesdecoded] = '\0';
    return bufplain;
}

