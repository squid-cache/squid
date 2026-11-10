/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_FIELDPARSER_H
#define SQUID_SRC_HTTP_ONE_FIELDPARSER_H

#include "http/one/Parser.h"
#include "HttpHeader.h"
#include "parser/Tokenizer.h"

namespace Http {
namespace One {

/** HTTP/1.x header field parser
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the field-lines of an HTTP/1 message:
 *
 * RFC 9112 section 5:
 *  field-line   = field-name ":" OWS field-value OWS
 */
class FieldParser : public Http1::Parser
{
public:
    FieldParser(const SBuf &, const http_hdr_owner_type &);

    /// extract a field name and value from the buffer being parsed.
    void parseFieldLine(SBuf &name, SBuf &value);

    /* Http1::Parser API */
    void clear() { tok.reset(SBuf()); }
    bool parse(const SBuf &newBuf) override { const bool e = tok.atEnd(); tok.reset(newBuf); return e; }

private:
    SBuf parseFieldName();
    SBuf parseFieldValue();

    /* Http1::Parser API */
    size_type firstLineSize() const override { return 0; }

    // Whether a request or response message is being parsed.
    // Some parser validation and tolerance depends on type.
    const http_hdr_owner_type msgType;

    // low-level tokenizer to use for parsing.
    // owns and manages the buffer being parsed.
    Http1::Parser::Tokenizer tok;
};

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_FIELDPARSER_H */
