/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_TOKENIZER_H
#define SQUID_SRC_HTTP_ONE_TOKENIZER_H

class SBuf;

namespace Parser {
class Tokenizer;
}

namespace Http {
namespace One {

/**
 * Attempt to parse a (token / quoted-string ) lexical construct.
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
 * \param escaped HTTP/1.0 does not permit \-escaped characters
 */
bool quotedStringOrToken(::Parser::Tokenizer &tok, SBuf &value, const bool http1p0 = false);

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TOKENIZER_H */

