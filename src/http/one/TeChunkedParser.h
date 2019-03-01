/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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

using ::Parser::InsufficientInput;

// TODO: Move this class into http/one/ChunkExtensionValueParser.*
/// A customizable parser of a single chunk extension value (chunk-ext-val).
/// From RFC 7230 section 4.1.1 and its Errata #4667:
/// chunk-ext = *( BWS  ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
/// chunk-ext-name = token
/// chunk-ext-val  = token / quoted-string
class ChunkExtensionValueParser
{
public:
    typedef ::Parser::Tokenizer Tokenizer;

    /// extracts and ignores the value of a named extension
    static void Ignore(Tokenizer &tok, const SBuf &extName);

    /// extracts and then interprets (or ignores) the extension value
    virtual void parse(Tokenizer &tok, const SBuf &extName) = 0;
};

/**
 * An incremental parser for chunked transfer coding
 * defined in RFC 7230 section 4.1.
 * http://tools.ietf.org/html/rfc7230#section-4.1
 *
 * The parser shovels content bytes from the raw
 * input buffer into the content output buffer, both caller-supplied.
 * Chunk extensions like use-original-body are handled via parseExtensionValuesWith().
 * Trailers are available via mimeHeader() if wanted.
 */
class TeChunkedParser : public Http1::Parser
{
public:
    TeChunkedParser();
    virtual ~TeChunkedParser() { theOut=nullptr; /* we do not own this object */ }

    /// set the buffer to be used to store decoded chunk data
    void setPayloadBuffer(MemBuf *parsedContent) {theOut = parsedContent;}

    /// Instead of ignoring all chunk extension values, give the supplied
    /// parser a chance to handle them. Only applied to last-chunk (for now).
    void parseExtensionValuesWith(ChunkExtensionValueParser *parser) { customExtensionValueParser = parser; }

    bool needsMoreSpace() const;

    /* Http1::Parser API */
    virtual void clear();
    virtual bool parse(const SBuf &);
    virtual Parser::size_type firstLineSize() const {return 0;} // has no meaning with multiple chunks

private:
    bool parseChunkSize(Tokenizer &tok);
    bool parseChunkMetadataSuffix(Tokenizer &);
    void parseChunkExtensions(Tokenizer &);
    void parseOneChunkExtension(Tokenizer &);
    bool parseChunkBody(Tokenizer &tok);
    bool parseChunkEnd(Tokenizer &tok);

    MemBuf *theOut;
    uint64_t theChunkSize;
    uint64_t theLeftBodySize;

    /// An optional plugin for parsing and interpreting custom chunk-ext-val.
    /// This "visitor" object is owned by our creator.
    ChunkExtensionValueParser *customExtensionValueParser;
};

} // namespace One
} // namespace Http

#endif /* SQUID_SRC_HTTP_ONE_TeChunkedParser_H */

