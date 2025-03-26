/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 55    HTTP Header Field Parser */

#include "squid.h"
#include "base/CharacterSet.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "http/FieldParser.h"
#include "parser/Tokenizer.h"

/**
 * Governed by RFC 9110 section 5.1:
 *
 *  field-name     = token
 *  token          = 1*TCHAR
 */
void
Http::FieldParser::parseFieldName(::Parser::Tokenizer &tok)
{
    if (!tok.prefix(theName, CharacterSet::TCHAR))
        throw TextException(SBuf("missing field name"), Here());

    /* is it a "known" field? */
    theId = Http::HeaderLookupTable.lookup(theName.rawContent(),theName.length()).id;
    debugs(55, 9, "got hdr-id=" << id());
    if (id() == Http::HdrType::BAD_HDR) {
        theId = Http::HdrType::OTHER;
    } else {
        ++ FieldStats(id()).seenCount;
        if (id() != Http::HdrType::OTHER)
            theName = Http::HeaderLookupTable.lookup(id()).name;
    }
}

/**
 * Governed by RFC 9110 section 5.5:
 *
 *  field-value    = *field-content
 *  field-content  = field-vchar
 *                   [ 1*( SP / HTAB / field-vchar ) field-vchar ]
 *  field-vchar    = VCHAR / obs-text
 *  obs-text       = %x80-FF
 */
void
Http::FieldParser::parseFieldValue(::Parser::Tokenizer &tok)
{
    static const CharacterSet fvCharacters =
        (CharacterSet::VCHAR +
         CharacterSet::WSP +
         CharacterSet::OBSTEXT).rename("field-value");

    // may be missing
    (void)tok.prefix(theValue, fvCharacters);
}

HttpHeaderFieldStat &
Http::FieldStats(const HdrType id)
{
    static HttpHeaderFieldStat bad;
    if (id == HdrType::BAD_HDR) {
        // 'bad header' stats are not to be kept in the table
        return bad = HttpHeaderFieldStat();
    }

    static std::vector<HttpHeaderFieldStat> stats(Http::HdrType::enumEnd_);
    return stats[id];
}
