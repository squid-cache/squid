/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "html/Quoting.h"

#include <array>
#include <cstring>


static const auto & MakeEscapeSequences()
{
    static std::array<std::pair<unsigned char, const char *>, 5> const escapePairs = {
        std::make_pair('<', "&lt;"),
        std::make_pair('>', "&gt;"),
        std::make_pair('"', "&quot;"),
        std::make_pair('&', "&amp;"),
        std::make_pair('\'', "&apos;")
    };
    static auto escapeMap = new std::array<const char *, 256>{};
    if ((*escapeMap)['<']) {
        return *escapeMap;
    }
    const size_t maxEscapeLength = 7;
    /* Encode control chars just to be on the safe side, and make
     * sure all 8-bit characters are encoded to protect from buggy
     * clients
     */
    for (uint32_t ch = 0; ch < 256; ++ch) {
        if ((ch <= 0x1F || ch >= 0x7f) && ch != '\n' && ch != '\r' && ch != '\t') {
            (*escapeMap)[ch] = static_cast<char *>(xcalloc(maxEscapeLength, 1));
            snprintf(const_cast<char*>((*escapeMap)[ch]), sizeof escapeMap[ch], "&#%d;", static_cast<int>(ch));
        }
    }
    for (auto &pair: escapePairs) {
        (*escapeMap)[pair.first] = static_cast<char *>(xcalloc(maxEscapeLength, 1));
        xstrncpy(const_cast<char*>((*escapeMap)[pair.first]), pair.second, maxEscapeLength);
    }
    return *escapeMap;
}


char *
html_quote(const char *string)
{
    static const auto htmlSpecialCharacters = MakeEscapeSequences();

    static char *buf;
    static size_t bufsize = 0;
    const char *src;
    char *dst;

    /* XXX This really should be implemented using a MemPool, but
     * MemPools are not yet available in lib...
     */
    if (!buf || strlen(string) * 6 > bufsize) {
        xfree(buf);
        bufsize = strlen(string) * 6 + 1;
        buf = static_cast<char *>(xcalloc(bufsize, 1));
    }
    for (src = string, dst = buf; *src; src++) {
        const unsigned char ch = *src;

        if (const auto escape = htmlSpecialCharacters[ch]) {
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

