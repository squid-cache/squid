/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_TOKENIZER_H
#define SQUID_SRC_HTTP_ONE_TOKENIZER_H

#include "parser/forward.h"
#include "sbuf/forward.h"

namespace Http {
namespace One {

/**
 * Extracts either an HTTP/1 token or quoted-string while dealing with
 * possibly incomplete input typical for incremental text parsers.
 * Unescapes escaped characters in HTTP/1.1 quoted strings.
 *
 * \param http1p0 whether to prohibit \-escaped characters in quoted strings
 * \throws InsufficientInput as appropriate, including on unterminated tokens
 * \returns extracted token or quoted string (without quotes)
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
 */
SBuf tokenOrQuotedString(Parser::Tokenizer &tok, const bool http1p0 = false);

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TOKENIZER_H */

