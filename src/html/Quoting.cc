/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "html/Quoting.h"
#include "sbuf/SBuf.h"

#include <array>
#include <cstring>

static const auto &
EscapeSequences()
{
    static auto escapeMap = new std::array<SBuf, 256> {};
    auto &em = *escapeMap;
    if (!em['<'].isEmpty())
        return em;

    // Encode control chars just to be on the safe side and make sure all 8-bit
    // characters are encoded to protect from buggy clients.
    for (int ch = 0; ch < 256; ++ch) {
        if ((ch <= 0x1F || ch >= 0x7f) && ch != '\n' && ch != '\r' && ch != '\t') {
            em[ch] = SBuf().Printf("&#%d;", ch);
        }
    }

    em['<'] = "&lt;";
    em['>'] = "&gt;";
    em['"'] = "&quot;";
    em['&'] = "&amp;";
    em['\''] = "&apos;";

    return em;
}

char *
html_quote(const char *string)
{
    static const auto &escapeSequences = EscapeSequences();
    static char *buf = nullptr;
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

        const auto &escape = escapeSequences[ch];
        if (!escape.isEmpty()) {
            /* Ok, An escaped form was found above. Use it */
            escape.copy(dst, 7);
            dst += escape.length();
        } else {
            /* Apparently there is no need to escape this character */
            *dst++ = ch;
        }
    }
    /* Nullterminate and return the result */
    *dst = '\0';
    return (buf);
}

