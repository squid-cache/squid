/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/one/Tokenizer.h"
#include "parser/Tokenizer.h"

bool
Http::One::quotedStringOrToken(::Parser::Tokenizer &tok, SBuf &returnedToken, const bool http1p0)
{
    if (!tok.skip('"'))
        return tok.prefix(returnedToken, CharacterSet::TCHAR);

    // the initial DQUOTE has been skipped by the caller

    /*
     * RFC 1945 - defines qdtext:
     *   inclusive of LWS (which includes CR and LF)
     *   exclusive of 0x80-0xFF
     *   includes 0x5C ('\') as just a regular character
     */
    static const CharacterSet qdtext1p0 = CharacterSet("qdtext (HTTP/1.0)", 0x23, 0x7E) +
                                          CharacterSet("", "!") +
                                          CharacterSet::CR + CharacterSet::LF + CharacterSet::HTAB + CharacterSet::SP;
    /*
     * RFC 7230 - defines qdtext:
     *   exclusive of CR and LF
     *   inclusive of 0x80-0xFF
     *   includes 0x5C ('\') but only when part of quoted-pair
     */
    static const CharacterSet qdtext1p1 = CharacterSet("qdtext (HTTP/1.1)", 0x23, 0x5B) +
                                          CharacterSet("", "!") +
                                          CharacterSet("", 0x5D, 0x7E) +
                                          CharacterSet::HTAB + CharacterSet::SP +
                                          CharacterSet::OBSTEXT;

    // best we can do is a conditional reference since http1p0 value may change per-client
    const CharacterSet &tokenChars = (http1p0 ? qdtext1p0 : qdtext1p1);

    while (!tok.atEnd()) {
        if (tok.skip('"'))
            return true;

        SBuf qdText;
        if (tok.prefix(qdText, tokenChars))
            returnedToken.append(qdText);
        else if (!http1p0 && tok.skip('\\')) { // HTTP/1.1 allows quoted-pair, HTTP/1.0 does not
            /* RFC 7230 section 3.2.6
             *
             * The backslash octet ("\") can be used as a single-octet quoting
             * mechanism within quoted-string and comment constructs.  Recipients
             * that process the value of a quoted-string MUST handle a quoted-pair
             * as if it were replaced by the octet following the backslash.
             *
             *   quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
             */
            static const CharacterSet qPairChars = CharacterSet::HTAB + CharacterSet::SP + CharacterSet::VCHAR + CharacterSet::OBSTEXT;
            SBuf escaped;
            if (!tok.prefix(escaped, qPairChars, 1))
                break;

            returnedToken.append(escaped);
        } else {
            debugs(24, 8, "invalid bytes for set " << tokenChars.name);
            break;
        }
    }

    returnedToken.clear();
    return false;
}

