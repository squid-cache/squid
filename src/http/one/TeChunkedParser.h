/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_TeChunkedParser_H
#define SQUID_SRC_HTTP_ONE_TeChunkedParser_H

#include "http/one/Parser.h"

class MemBuf;

namespace Http
{
namespace One
{

/// A base class for parsing custom chunked extensions.
class CustomExtensionsParser
{
public:
    typedef ::Parser::Tokenizer Tokenizer;

    /// parses the extension value and stores the parsed result
    virtual bool parse(Tokenizer &tok, const SBuf &extName) = 0;
    /// whether the parser is aware of the the given extension
    /// to call a subsequent parse() on it
    virtual bool knownExtension(const SBuf &extName) = 0;

protected:
    /// parses an extension's value as an integer
    bool parseIntExtension(Tokenizer &tok, const SBuf &name, int64_t &value);
};

/**
 * An incremental parser for chunked transfer coding
 * defined in RFC 7230 section 4.1.
 * http://tools.ietf.org/html/rfc7230#section-4.1
 *
 * The parser shovels content bytes from the raw
 * input buffer into the content output buffer, both caller-supplied.
 * Ignores chunk extensions except for ICAP's use-original-body.
 * Trailers are available via mimeHeader() if wanted.
 */
class TeChunkedParser : public Http1::Parser
{
public:
    TeChunkedParser();
    virtual ~TeChunkedParser() { theOut=nullptr; /* we do not own this object */ }

    /// set the buffer to be used to store decoded chunk data
    void setPayloadBuffer(MemBuf *parsedContent) {theOut = parsedContent;}

    /// delegate parsing of some extensions to an external parser
    void setCustomExtensionsParser(CustomExtensionsParser *parser) { customExtensionsParser = parser; }

    bool needsMoreSpace() const;

    /* Http1::Parser API */
    virtual void clear();
    virtual bool parse(const SBuf &);
    virtual Parser::size_type firstLineSize() const {return 0;} // has no meaning with multiple chunks

private:
    bool parseChunkSize(Tokenizer &tok);
    bool parseOneChunkExtension(Tokenizer &tok);
    bool parseChunkExtensions(Tokenizer &tok);
    bool parseChunkBody(Tokenizer &tok);
    bool parseChunkEnd(Tokenizer &tok);

    MemBuf *theOut;
    uint64_t theChunkSize;
    uint64_t theLeftBodySize;
    CustomExtensionsParser *customExtensionsParser;
};

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TeChunkedParser_H */

