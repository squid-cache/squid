/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/one/Parser.h"
#include "http/one/Tokenizer.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

/// Attempts to extract a token from the input, which is assumed to be
/// a quoted string with the initial '"' removed.
static bool
parseQuotedStringSuffix(Parser::Tokenizer &tok, SBuf &returnedToken, const bool http1p0)
{
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

    const auto savedTok = tok;
    SBuf parsedToken;

    while (!tok.atEnd()) {
        SBuf qdText;
        if (tok.prefix(qdText, tokenChars))
            parsedToken.append(qdText);
        if (!http1p0 && tok.skip('\\')) { // HTTP/1.1 allows quoted-pair, HTTP/1.0 does not
            if (tok.atEnd())
                break;
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
                throw TexcHere("invalid escaped characters");

            parsedToken.append(escaped);
            continue;
        } else if (tok.skip('"')) {
            returnedToken = parsedToken;
            return true;
        } else if (tok.atEnd()) {
            break;
        }
        throw TexcHere(ToSBuf("invalid bytes for set ", tokenChars.name));
    }

    tok = savedTok;
    return false; // need more data
}

bool
Http::One::tokenOrQuotedString(Parser::Tokenizer &tok, SBuf &returnedToken, const bool tokenPrefixResult, const bool http1p0)
{
    SBuf parsedToken;
    const auto savedTok = tok;
    if (tok.skip('"')) {
        if (!parseQuotedStringSuffix(tok, parsedToken, http1p0)) {
            tok = savedTok;
            return false;
        }
    } else {
        if (!tok.prefix(parsedToken, CharacterSet::TCHAR))
            return false;
        if (tok.atEnd() && !tokenPrefixResult) {
            tok = savedTok;
            return false;
        }
    }
    // got the complete token
    returnedToken = parsedToken;
    return true;
}

