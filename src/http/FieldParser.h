/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_FIELDPARSER_H
#define SQUID_SRC_HTTP_FIELDPARSER_H

#include "http/RegisteredHeaders.h"
#include "HttpHeader.h" // for http_hdr_owner_type
#include "HttpHeaderFieldStat.h"
#include "parser/forward.h"
#include "sbuf/SBuf.h"

namespace Http
{

class FieldParser
{
    MEMPROXY_CLASS(Http::FieldParser);

public:
    /// parse a field-name from the given tokenizer
    void parseFieldName(::Parser::Tokenizer &);

    /// parse a field-value from the given tokenizer
    void parseFieldValue(::Parser::Tokenizer &);

    /// the Squid internal ID for known fields, or HdrType::OTHER
    HdrType id() const { return theId; }

    /// the HTTP field-name
    SBuf name() const { return theName; }

    /// the HTTP field-value
    SBuf value() const { return theValue; }

private:
    HdrType theId;
    SBuf theName;
    SBuf theValue;
};

/// statistics counters for header fields.
HttpHeaderFieldStat &FieldStats(const HdrType);

} // namespace Http

#endif /* SQUID_SRC_HTTP_FIELDPARSER_H */
