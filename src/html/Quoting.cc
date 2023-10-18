/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "html/Quoting.h"

#include <cstring>
#include <unordered_map>


const std::unordered_map<char,const char *> htmlEntities = {
    {'<', "&lt;"},
    {'>', "&gt;"},
    {'"', "&quot;"},
    {'&', "&amp;"},
    {'\'', "&#39;"}
};
const CharacterSet htmlSpecialCharacters("html entities","<>&\"\'");

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

    /* XXX This really should be implemented using a MemPool, but
     * MemPools are not yet available in lib...
     */
    if (buf == NULL || strlen(string) * 6 > bufsize) {
        xfree(buf);
        bufsize = strlen(string) * 6 + 1;
        buf = static_cast<char*>(xcalloc(bufsize, 1));
    }
    for (src = string, dst = buf; *src; src++) {
        const char *escape = NULL;
        const unsigned char ch = *src;

        /* Walk thru the list of HTML Entities that must be quoted to
         * display safely
         */
        if (htmlSpecialCharacters[ch]) {
            escape = htmlEntities.at(ch); // guaranteed to exist
        }
        /* Encode control chars just to be on the safe side, and make
         * sure all 8-bit characters are encoded to protect from buggy
         * clients
         */
        if (!escape && (ch <= 0x1F || ch >= 0x7f) && ch != '\n' && ch != '\r' && ch != '\t') {
            static char dec_encoded[7];
            snprintf(dec_encoded, sizeof dec_encoded, "&#%d;", static_cast<int>(ch));
            escape = dec_encoded;
        }
        if (escape) {
            /* Ok, An escaped form was found above. Use it */
            strncpy(dst, escape, 7);
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

