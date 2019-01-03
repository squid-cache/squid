/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PROXYP_PARSER_H
#define SQUID_PROXYP_PARSER_H

#include "proxyp/forward.h"

class SBuf;

namespace ProxyProtocol {

/// successful parsing result
class Parsed
{
public:
    Parsed(const MessagePointer &parsedMessage, const size_t parsedSize);

    MessagePointer message; ///< successfully parsed message; not nil
    size_t size; ///< raw bytes parsed, including any magic/delimiters
};

/// Parses a PROXY protocol message from the buffer, determining
/// the protocol version (v1 or v2) by the leading magic string.
/// \throws Parser::BinaryTokenizer::InsufficientInput to ask for more data
/// \returns the successfully parsed message
Parsed Parse(const SBuf &);

} // namespace ProxyProtocol

#endif

