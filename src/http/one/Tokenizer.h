/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_TOKENIZER_H
#define SQUID_SRC_HTTP_ONE_TOKENIZER_H

#include "parser/Tokenizer.h"

namespace Http {
namespace One {

/**
 * Lexical processor extended to tokenize HTTP/1.x syntax.
 *
 * \see ::Parser::Tokenizer for more detail
 */
class Tokenizer : public ::Parser::Tokenizer
{
public:
    Tokenizer(SBuf &s) : ::Parser::Tokenizer(s), savedStats_(0) {}

    /**
     * Attempt to parse a quoted-string lexical construct.
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
    bool quotedString(SBuf &value, const bool http1p0 = false);

    /**
     * Attempt to parse a (token / quoted-string ) lexical construct.
     */
    bool quotedStringOrToken(SBuf &value, const bool http1p0 = false);

private:
    /// parse the internal component of a quote-string, and terminal DQUOTE
    bool qdText(SBuf &value, const bool http1p0);

    void checkpoint() { savedCheckpoint_ = buf(); savedStats_ = parsedSize(); }
    void restoreLastCheckpoint() { undoParse(savedCheckpoint_, savedStats_); }

    SBuf savedCheckpoint_;
    SBuf::size_type savedStats_;
};

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TOKENIZER_H */

