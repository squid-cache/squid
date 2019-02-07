/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "html_quote.h"

#if HAVE_STRING_H
#include <string.h>
#endif

/*
 *  HTML defines these characters as special entities that should be quoted.
 */
static struct {
    unsigned char code;
    const char *quote;
} htmlstandardentities[] =

{
    /* NOTE: The quoted form MUST not be larger than 6 character.
     * see close to the MemPool commend below
     */
    {
        '<', "&lt;"
    },
    {
        '>', "&gt;"
    },
    {
        '"', "&quot;"
    },
    {
        '&', "&amp;"
    },
    {
        '\'', "&#39;"
    },
    {
        0, NULL
    }
};

/*
 *  html_do_quote - Returns a static buffer containing the quoted
 *  string.
 */
char *
html_quote(const char *string)
{
    static char *buf;
    static size_t bufsize = 0;
    const char *src;
    char *dst;
    int i;

    /* XXX This really should be implemented using a MemPool, but
     * MemPools are not yet available in lib...
     */
    if (buf == NULL || strlen(string) * 6 > bufsize) {
        xfree(buf);
        bufsize = strlen(string) * 6 + 1;
        buf = xcalloc(bufsize, 1);
    }
    for (src = string, dst = buf; *src; src++) {
        const char *escape = NULL;
        const unsigned char ch = *src;

        /* Walk thru the list of HTML Entities that must be quoted to
         * display safely
         */
        for (i = 0; htmlstandardentities[i].code; i++) {
            if (ch == htmlstandardentities[i].code) {
                escape = htmlstandardentities[i].quote;
                break;
            }
        }
        /* Encode control chars just to be on the safe side, and make
         * sure all 8-bit characters are encoded to protect from buggy
         * clients
         */
        if (!escape && (ch <= 0x1F || ch >= 0x7f) && ch != '\n' && ch != '\r' && ch != '\t') {
            static char dec_encoded[7];
            snprintf(dec_encoded, sizeof dec_encoded, "&#%3d;", (int) ch);
            escape = dec_encoded;
        }
        if (escape) {
            /* Ok, An escaped form was found above. Use it */
            strncpy(dst, escape, 6);
            dst += strlen(escape);
        } else {
            /* Apparently there is no need to escape this character */
            *dst++ = ch;
        }
    }
    /* Nullterminate and return the result */
    *dst = '\0';
    return (buf);
}

