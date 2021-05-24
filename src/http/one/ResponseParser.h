/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_ONE_RESPONSEPARSER_H
#define _SQUID_SRC_HTTP_ONE_RESPONSEPARSER_H

#include "http/one/Parser.h"
#include "http/StatusCode.h"

namespace Http {
namespace One {

/** HTTP/1.x  protocol response parser
 *
 * Also capable of parsing unexpected ICY responses and
 * upgrading HTTP/0.9 syntax responses to HTTP/1.1
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the major CRLF delimited segments of an HTTP/1 respone message:
 *
 * \li status-line (version SP status SP reash-phrase)
 * \li mime-header (set of RFC2616 syntax header fields)
 */
class ResponseParser : public Http1::Parser
{
public:
    ResponseParser() = default;
    ResponseParser(const ResponseParser &) = default;
    ResponseParser &operator =(const ResponseParser &) = default;
    ResponseParser(ResponseParser &&) = default;
    ResponseParser &operator =(ResponseParser &&) = default;
    virtual ~ResponseParser() {}

    /* Http::One::Parser API */
    virtual void clear() {*this=ResponseParser();}
    virtual Http1::Parser::size_type firstLineSize() const;
    virtual bool parse(const SBuf &aBuf);

    /* respone specific fields, read-only */
    Http::StatusCode messageStatus() const { return statusCode_;}
    SBuf reasonPhrase() const { return reasonPhrase_;}

    /// extracts response status-code and the following delimiter; validates status-code
    /// \param[out] code syntactically valid status-code (unchanged on syntax errors)
    /// \throws InsuffientInput and other exceptions on syntax and validation errors
    static void ParseResponseStatus(Tokenizer &, StatusCode &code);

private:
    int parseResponseFirstLine();
    int parseResponseStatusAndReason(Tokenizer &);

    /// magic prefix for identifying ICY response messages
    static const SBuf IcyMagic;

    /// Whether we found the status code yet.
    /// We cannot rely on status value because server may send "000".
    bool completedStatus_ = false;

    /// HTTP/1 status-line status code
    Http::StatusCode statusCode_ = Http::scNone;

    /// HTTP/1 status-line reason phrase
    SBuf reasonPhrase_;
};

} // namespace One
} // namespace Http

#endif /* _SQUID_SRC_HTTP_ONE_RESPONSEPARSER_H */

