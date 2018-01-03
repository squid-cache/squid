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

/**
 * An incremental parser for chunked transfer coding
 * defined in RFC 7230 section 4.1.
 * http://tools.ietf.org/html/rfc7230#section-4.1
 *
 * The parser shovels content bytes from the raw
 * input buffer into the content output buffer, both caller-supplied.
 * Ignores chunk extensions except for ICAP's ieof.
 * Trailers are available via mimeHeader() if wanted.
 */
class TeChunkedParser : public Http1::Parser
{
public:
    TeChunkedParser();
    virtual ~TeChunkedParser() {theOut=NULL;/* we dont own this object */}

    /// set the buffer to be used to store decoded chunk data
    void setPayloadBuffer(MemBuf *parsedContent) {theOut = parsedContent;}

    bool needsMoreSpace() const;

    /* Http1::Parser API */
    virtual void clear();
    virtual bool parse(const SBuf &);
    virtual Parser::size_type firstLineSize() const {return 0;} // has no meaning with multiple chunks

private:
    bool parseChunkSize(Http1::Tokenizer &tok);
    bool parseChunkExtension(Http1::Tokenizer &tok, bool skipKnown);
    bool parseChunkBody(Http1::Tokenizer &tok);
    bool parseChunkEnd(Http1::Tokenizer &tok);

    MemBuf *theOut;
    uint64_t theChunkSize;
    uint64_t theLeftBodySize;

public:
    int64_t useOriginBody;
};

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TeChunkedParser_H */

