/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "http/one/TeChunkedParser.h"
#include "http/one/Tokenizer.h"
#include "http/ProtocolVersion.h"
#include "MemBuf.h"
#include "parser/Tokenizer.h"
#include "Parsing.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

Http::One::TeChunkedParser::TeChunkedParser():
    customExtensionValueParser(nullptr)
{
    // chunked encoding only exists in HTTP/1.1
    Http1::Parser::msgProtocol_ = Http::ProtocolVersion(1,1);

    clear();
}

void
Http::One::TeChunkedParser::clear()
{
    parsingStage_ = Http1::HTTP_PARSE_NONE;
    buf_.clear();
    theChunkSize = theLeftBodySize = 0;
    theOut = NULL;
    // XXX: We do not reset customExtensionValueParser here. Based on the
    // clear() API description, we must, but it makes little sense and could
    // break method callers if they appear because some of them may forget to
    // reset customExtensionValueParser. TODO: Remove Http1::Parser as our
    // parent class and this unnecessary method with it.
}

bool
Http::One::TeChunkedParser::parse(const SBuf &aBuf)
{
    buf_ = aBuf; // sync buffers first so calls to remaining() work properly if nothing done.

    if (buf_.isEmpty()) // nothing to do (yet)
        return false;

    debugs(74, DBG_DATA, "Parse buf={length=" << aBuf.length() << ", data='" << aBuf << "'}");

    Must(!buf_.isEmpty() && theOut);

    if (parsingStage_ == Http1::HTTP_PARSE_NONE)
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_SZ;

    Tokenizer tok(buf_);

    // loop for as many chunks as we can
    // use do-while instead of while so that we can incrementally
    // restart in the middle of a chunk/frame
    do {

        if (parsingStage_ == Http1::HTTP_PARSE_CHUNK_EXT && !parseChunkMetadataSuffix(tok))
            return false;

        if (parsingStage_ == Http1::HTTP_PARSE_CHUNK && !parseChunkBody(tok))
            return false;

        if (parsingStage_ == Http1::HTTP_PARSE_MIME && !grabMimeBlock("Trailers", 64*1024 /* 64KB max */))
            return false;

        // loop for as many chunks as we can
    } while (parsingStage_ == Http1::HTTP_PARSE_CHUNK_SZ && parseChunkSize(tok));

    return !needsMoreData() && !needsMoreSpace();
}

bool
Http::One::TeChunkedParser::needsMoreSpace() const
{
    assert(theOut);
    return parsingStage_ == Http1::HTTP_PARSE_CHUNK && !theOut->hasPotentialSpace();
}

/// RFC 7230 section 4.1 chunk-size
bool
Http::One::TeChunkedParser::parseChunkSize(Tokenizer &tok)
{
    Must(theChunkSize <= 0); // Should(), really

    int64_t size = -1;
    if (tok.int64(size, 16, false) && !tok.atEnd()) {
        if (size < 0)
            throw TexcHere("negative chunk size");

        theChunkSize = theLeftBodySize = size;
        debugs(94,7, "found chunk: " << theChunkSize);
        buf_ = tok.remaining(); // parse checkpoint
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_EXT;
        return true;

    } else if (tok.atEnd()) {
        return false; // need more data
    }

    // else error
    throw TexcHere("corrupted chunk size");
    return false; // should not be reachable
}

/// Parses "[chunk-ext] CRLF" from RFC 7230 section 4.1.1:
///   chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
///   last-chunk = 1*"0" [ chunk-ext ] CRLF
bool
Http::One::TeChunkedParser::parseChunkMetadataSuffix(Tokenizer &tok)
{
    // Code becomes much simpler when incremental parsing functions throw on
    // bad or insufficient input, like in the code below. TODO: Expand up.
    try {
        parseChunkExtensions(tok); // a possibly empty chunk-ext list
        skipLineTerminator(tok);
        buf_ = tok.remaining();
        parsingStage_ = theChunkSize ? Http1::HTTP_PARSE_CHUNK : Http1::HTTP_PARSE_MIME;
        return true;
    } catch (const InsufficientInput &) {
        tok.reset(buf_); // backtrack to the last commit point
        return false;
    }
    // other exceptions bubble up to kill message parsing
}

/// Parses the chunk-ext list (RFC 7230 section 4.1.1 and its Errata #4667):
/// chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
void
Http::One::TeChunkedParser::parseChunkExtensions(Tokenizer &tok)
{
    do {
        ParseBws(tok); // Bug 4492: IBM_HTTP_Server sends SP after chunk-size

        if (!tok.skip(';'))
            return; // reached the end of extensions (if any)

        parseOneChunkExtension(tok);
        buf_ = tok.remaining(); // got one extension
    } while (true);
}

void
Http::One::ChunkExtensionValueParser::Ignore(Tokenizer &tok, const SBuf &extName)
{
    const auto ignoredValue = tokenOrQuotedString(tok);
    debugs(94, 5, extName << " with value " << ignoredValue);
}

/// Parses a single chunk-ext list element:
/// chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
void
Http::One::TeChunkedParser::parseOneChunkExtension(Tokenizer &tok)
{
    ParseBws(tok); // Bug 4492: ICAP servers send SP before chunk-ext-name

    const auto extName = tok.prefix("chunk-ext-name", CharacterSet::TCHAR);

    ParseBws(tok);

    if (!tok.skip('='))
        return; // parsed a valueless chunk-ext

    ParseBws(tok);

    // optimization: the only currently supported extension needs last-chunk
    if (!theChunkSize && customExtensionValueParser)
        customExtensionValueParser->parse(tok, extName);
    else
        ChunkExtensionValueParser::Ignore(tok, extName);
}

bool
Http::One::TeChunkedParser::parseChunkBody(Tokenizer &tok)
{
    if (theLeftBodySize > 0) {
        buf_ = tok.remaining(); // sync buffers before buf_ use

        // TODO fix type mismatches and casting for these
        const size_t availSize = min(theLeftBodySize, (uint64_t)buf_.length());
        const size_t safeSize = min(availSize, (size_t)theOut->potentialSpaceSize());

        theOut->append(buf_.rawContent(), safeSize);
        buf_.consume(safeSize);
        theLeftBodySize -= safeSize;

        tok.reset(buf_); // sync buffers after consume()
    }

    if (theLeftBodySize == 0)
        return parseChunkEnd(tok);
    else
        Must(needsMoreData() || needsMoreSpace());

    return true;
}

bool
Http::One::TeChunkedParser::parseChunkEnd(Tokenizer &tok)
{
    Must(theLeftBodySize == 0); // Should(), really

    try {
        skipLineTerminator(tok);
        buf_ = tok.remaining(); // parse checkpoint
        theChunkSize = 0; // done with the current chunk
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_SZ;
        return true;
    }
    catch (const InsufficientInput &) {
        return false;
    }
    // other exceptions bubble up to kill message parsing
}

