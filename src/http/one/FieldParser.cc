/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "http/one/FieldParser.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "debug/Stream.h"

Http::One::FieldParser::FieldParser(const SBuf &aBuf, const http_hdr_owner_type &aType) :
    Http::One::Parser(),
    msgType(aType),
    tok(aBuf)
{}

/**
 * RFC 9112 section 5:
 *
 *  field-line   = field-name ":" OWS field-value OWS
 */
void
Http::One::FieldParser::parseFieldLine(SBuf &name, SBuf &value)
{
    name = parseFieldName(); // consumes ':' delimiter
    value = parseFieldValue();

    if (!tok.atEnd())
        skipLineTerminator(tok);
}

/**
 * RFC 9110 section 5.1:
 *
 *  field-name   = token
 *  token        = 1*TCHAR
 */
SBuf
Http::One::FieldParser::parseFieldName()
{
    auto name = tok.prefix("field-name", CharacterSet::TCHAR);

    /*
     * RFC 9112 section 5.1:
     * "No whitespace is allowed between the field name and colon.
     * ...
     *  A server MUST reject, with a response status code of 400 (Bad Request),
     *  any received request message that contains whitespace between a header
     *  field name and colon.  A proxy MUST remove any such whitespace from a
     *  response message before forwarding the message downstream."
     */
    const bool stripWhitespace = (msgType == hoReply) || Config.onoff.relaxed_header_parser;
    if (stripWhitespace && tok.skipAll(Http1::Parser::WhitespaceCharacters())) {
        // TODO: reduce log spam from 'tok.buf()' below
        debugs(11, Config.onoff.relaxed_header_parser <= 0 ? 2 : 3,
               "WARNING: Whitespace after field-name '" << name << tok.buf() << "'");
    }

    if(!tok.skip(':'))
        throw TextException("invalid field-name", Here());

    if (name.length() == 0)
        throw TextException("missing field-name", Here());

    if (name.length() > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        // TODO: update this to show proper name.length()  in Raw markup, but not print all that
        throw TextException(ToSBuf("huge field-line (", Raw("field-name", name.c_str(), 100), "...)"), Here());
    }

    return name;
}

/**
 * RFC 9110 section 5.1:
 *
 *  field-value    = *field-content
 *  field-content  = field-vchar
 *                   [ 1*( SP / HTAB / field-vchar ) field-vchar ]
 *  field-vchar    = VCHAR / obs-text
 *  obs-text       = %x80-FF
 */
SBuf
Http::One::FieldParser::parseFieldValue()
{
    static const CharacterSet fvChars = (CharacterSet::VCHAR + CharacterSet::OBSTEXT).rename("field-value");
    auto value = tok.prefix("field-value", fvChars);

    /**
     * RFC 9110 section 5.5:
     *   field value does not include leading or trailing whitespace.
     *   ... parsing implementation MUST exclude such whitespace prior
     *    to evaluating the field value
     */
    const auto start = value.findFirstNotOf(Http1::Parser::WhitespaceCharacters());
    const auto end = value.findLastNotOf(Http1::Parser::WhitespaceCharacters());
    value.chop(start, (end-start));

    if (value.length() > 65534) {
        /* String must be LESS THAN 64K and it adds a terminating NULL */
        // TODO: update this to show proper length() in Raw markup, but not print all that
        throw TextException(ToSBuf("huge field-line (", Raw("field-value", value.c_str(), 100), "...)"), Here());
    }

    return value;
}
