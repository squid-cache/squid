/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_ONE_REQUESTPARSER_H
#define _SQUID_SRC_HTTP_ONE_REQUESTPARSER_H

#include "http/one/Parser.h"
#include "http/RequestMethod.h"

namespace Parser {
class Tokenizer;
}

namespace Http {
namespace One {

/** HTTP/1.x protocol request parser
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the major CRLF delimited segments of an HTTP/1 request message:
 *
 * \item request-line (method, URL, protocol, version)
 * \item mime-header (set of RFC2616 syntax header fields)
 */
class RequestParser : public Http1::Parser
{
public:
    explicit RequestParser(bool preserveParsed = false);
    virtual ~RequestParser() {}

    /* Http::One::Parser API */
    virtual void clear() {*this = RequestParser();}
    virtual Http1::Parser::size_type firstLineSize() const;
    virtual bool parse(const SBuf &aBuf);

    /// the HTTP method if this is a request message
    const HttpRequestMethod & method() const {return method_;}

    /// the request-line URI if this is a request message, or an empty string.
    const SBuf &requestUri() const {return uri_;}

    /// the accumulated parsed bytes
    const SBuf &parsed() const { Must(preserveParsed_); return parsed_; }

private:
    void skipGarbageLines();
    int parseRequestFirstLine();
    /// called from parse() to do the parsing
    bool doParse(const SBuf &aBuf);

    /* all these return false and set parseStatusCode on parsing failures */
    bool parseMethodField(Http1::Tokenizer &);
    bool parseUriField(Http1::Tokenizer &);
    bool parseHttpVersionField(Http1::Tokenizer &);
    bool skipDelimiter(const size_t count, const char *where);
    bool skipTrailingCrs(Http1::Tokenizer &tok);

    bool http0() const {return !msgProtocol_.major;}
    static const CharacterSet &RequestTargetCharacters();

    /// what request method has been found on the first line
    HttpRequestMethod method_;

    /// raw copy of the original client request-line URI field
    SBuf uri_;

    /// all parsed bytes (i.e., input prefix consumed by parse() calls)
    /// meaningless unless preserveParsed_ is true
    SBuf parsed_;
    bool preserveParsed_; ///< whether to accumulate parsed bytes (in parsed_)
};

} // namespace One
} // namespace Http

#endif /*  _SQUID_SRC_HTTP_ONE_REQUESTPARSER_H */

