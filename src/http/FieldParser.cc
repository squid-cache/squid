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
#include "base/Raw.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "http/FieldParser.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"

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

    // TODO: remove when String is gone from Squid
    if (name().length() > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        debugs(55, 2, "ignoring huge header field (" <<
               Raw("field_start", name().rawContent(), 100) <<
               "...[skip " << name().length()-100 << " characters])");
        throw TextException(SBuf("huge-header-name"), Here());
    }

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

    // TODO: remove when String is gone from Squid
    if (value().length() > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        throw TextException(ToSBuf("'", name(), "' header of ", value().length(), " bytes"), Here());
    }
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
