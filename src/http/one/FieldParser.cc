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
#include "http/one/FieldParser.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

/**
 * Governed by RFC 9112 section 5:
 *
 *  field-line   = field-name ":" OWS field-value OWS
 */
void
Http1::FieldParser::parseFieldLine(::Parser::Tokenizer &tok, const http_hdr_owner_type msgType)
{
    // Isolate the: field-name
    parseFieldName(tok);

    // TODO: remove when String is gone from Squid
    if (name().length() > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        debugs(55, 2, "ignoring huge header field (" <<
               Raw("field_start", name().rawContent(), 100) <<
               "...[skip " << name().length()-100 << " characters])");
        throw TextException(SBuf("huge-header-name"), Here());
    }

    // handle delimiter ( BWS ":" ) or abort
    skipColonDelimiter(tok, msgType);

    // Isolate the: OWS field-value OWS
    (void)tok.skipAll(CharacterSet::WSP); // at least an SP expected
    parseFieldValue(tok);
    (void)tok.skipAll(CharacterSet::WSP);

    // TODO: remove when String is gone from Squid
    if (value().length() > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        throw TextException(ToSBuf("'", name(), "' header of ", value().length(), " bytes"), Here());
    }

    if (!tok.atEnd()) {
        const auto garbage = tok.remaining();
        const auto limit = min(garbage.length(), SBuf::size_type(100));
        throw TextException(ToSBuf(name() , " has invalid ", Raw("field-value", garbage.rawContent(), limit), "..."), Here());
    }
}

/**
 * Skip the field-line ":" delimiter.
 * Maybe tolerate whitespace before it depending on message type and
 * configured strict/relaxed parse setting.
 *
 * Governed by RFC 9112 section 5.1:
 *
 *  No whitespace is allowed between the header field-name and colon.
 * ...
 *  A server MUST reject any received request message that contains
 *  whitespace between a header field-name and colon with a response code
 *  of 400 (Bad Request).  A proxy MUST remove any such whitespace from a
 *  response message before forwarding the message downstream.
 */
void
Http1::FieldParser::skipColonDelimiter(::Parser::Tokenizer &tok, const http_hdr_owner_type msgType)
{
    if (tok.skip(':'))
        return;

    // Bad message syntax. Maybe tolerate whitespace.

    if (msgType == hoRequest)
        throw TextException(SBuf("invalid field-name"), Here());

    // for now, also let relaxed parser remove this BWS from any non-HTTP messages
    const bool stripWhitespace = (msgType == hoReply) ||
                                 Config.onoff.relaxed_header_parser;
    if (!stripWhitespace) // reject if we cannot strip
        throw TextException(SBuf("invalid field-name"), Here());

    if (const auto wspCount = tok.skipAll(CharacterSet::WSP)) {
        const auto garbage = tok.remaining();
        const auto limit = min(garbage.length(), SBuf::size_type(100));
        debugs(55, Config.onoff.relaxed_header_parser <= 0 ? 1 : 2,
               "WARNING: Whitespace after header name in '" <<
               Raw("field-name", garbage.rawContent(), limit) << "...");
    }

    // now MUST be the colon
    if (!tok.skip(':'))
        throw TextException(SBuf("invalid field-name"), Here());
}
