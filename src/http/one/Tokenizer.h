/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_TOKENIZER_H
#define SQUID_SRC_HTTP_ONE_TOKENIZER_H

#include "parser/forward.h"

class SBuf;

namespace Http {
namespace One {

/**
 * Extracts either an HTTP/1 token or a complete HTTP/1
 * quoted-string (and sets the quoted accordingly).
 * Unescapes escaped characters in HTTP/1.1 quoted strings.
 *
 * Governed by:
 *  - RFC 1945 section 2.1
 *  "
 *    A string of text is parsed as a single word if it is quoted using
 *    double-quote marks.
 *
 *        quoted-string  = ( <"> *(qdtext) <"> )
 *
 *        qdtext         = <any CHAR except <"> and CTLs,
 *                         but including LWS>
 *
 *    Single-character quoting using the backslash ("\") character is not
 *    permitted in HTTP/1.0.
 *  "
 *
 *  - RFC 7230 section 3.2.6
 *  "
 *    A string of text is parsed as a single value if it is quoted using
 *    double-quote marks.
 *
 *    quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 *    qdtext         = HTAB / SP /%x21 / %x23-5B / %x5D-7E / obs-text
 *    obs-text       = %x80-FF
 *  "
 *
 * \param http1p0 HTTP/1.0 does not permit \-escaped characters
 * \param tokenPrefixResult function return value when input is a token prefix
 * \returns tokenPrefixResult if input contains nothing but a token (prefix)
 * \returns true (and sets the value) if input starts with a token or quoted-string
 * \returns false (and leaves the value intact) if input does not start with a token or quoted-string
 * \throws on syntax violations
 * The function extracts parsed input and sets the value only when returning a true result.
 */
bool tokenOrQuotedString(Parser::Tokenizer &tok, SBuf &value, const bool tokenPrefixResult, const bool http1p0 = false);

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TOKENIZER_H */

