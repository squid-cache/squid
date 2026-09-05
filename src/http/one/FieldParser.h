/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_FIELDPARSER_H
#define SQUID_SRC_HTTP_ONE_FIELDPARSER_H

#include "http/FieldParser.h"

namespace Http
{
namespace One
{
class FieldParser : public Http::FieldParser
{
    MEMPROXY_CLASS(Http1::FieldParser);

public:
    /// parse an HTTP header field from the given tokenizer
    void parseFieldLine(::Parser::Tokenizer &, const http_hdr_owner_type);

private:
    void skipColonDelimiter(::Parser::Tokenizer &, const http_hdr_owner_type);
};

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_FIELDPARSER_H */
