/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PROXYP_PARSER_H
#define SQUID_SRC_PROXYP_PARSER_H

#include "proxyp/forward.h"
#include "sbuf/forward.h"

namespace ProxyProtocol {

/// successful parsing result
class Parsed
{
public:
    Parsed(const HeaderPointer &parsedHeader, const size_t parsedSize);

    HeaderPointer header; ///< successfully parsed header; not nil
    size_t size; ///< raw bytes parsed, including any magic/delimiters
};

/// Parses a PROXY protocol header from the buffer, determining
/// the protocol version (v1 or v2) by the leading magic string.
/// \throws Parser::BinaryTokenizer::InsufficientInput to ask for more data
/// \returns the successfully parsed header
Parsed Parse(const SBuf &);

} // namespace ProxyProtocol

#endif /* SQUID_SRC_PROXYP_PARSER_H */

