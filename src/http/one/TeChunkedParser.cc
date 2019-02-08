/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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

Http::One::TeChunkedParser::TeChunkedParser()
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
    useOriginBody = -1;
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

        if (parsingStage_ == Http1::HTTP_PARSE_CHUNK_EXT && !parseChunkExtensions(tok))
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

/**
 * Parses chunk metadata suffix, looking for interesting extensions and/or
 * getting to the line terminator. RFC 7230 section 4.1.1 and its Errata #4667:
 *
 *   chunk-ext = *( BWS  ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
 *   chunk-ext-name = token
 *   chunk-ext-val  = token / quoted-string
 *
 * ICAP 'use-original-body=N' extension is supported.
 */
bool
Http::One::TeChunkedParser::parseChunkExtensions(Tokenizer &tok)
{
    while (parseOneChunkExtension(tok)) {
        buf_ = tok.remaining(); // got one extension; there may be more
    }

    if (skipLineTerminatorIfAny(tok)) {
        buf_ = tok.remaining();
        parsingStage_ = theChunkSize ? Http1::HTTP_PARSE_CHUNK : Http1::HTTP_PARSE_MIME;
        return true; // reached the end of extensions (if any)
    }

    static const CharacterSet NonLF = (CharacterSet::LF).complement().rename("non-LF");
    if (tok.skipAll(NonLF) && tok.skip('\n'))
        throw TexcHere("cannot parse chunk extension"); // <garbage> CR*LF
    return false; // need more data
}

/// parses an extension's value as an integer
static bool
parseIntExtension(Parser::Tokenizer &tok, const SBuf &name, int64_t &value)
{
    assert(!tok.atEnd()); // guaranteed by ParseBws() after "="

    const auto savedTok = tok;
    int64_t parsedValue = 0;

    if (!tok.int64(parsedValue, 10))
        throw TexcHere(ToSBuf("invalid value for the decimal integer chunk extension ", name));

    if (!tok.atEnd()) {
        value = parsedValue;
        return true;
    }

    tok = savedTok;
    return false;
}

bool
Http::One::TeChunkedParser::parseOneChunkExtension(Tokenizer &tok)
{
    const auto savedTok = tok;
    SBuf extName;

    if (!ParseBws(tok) || // Bug 4492: IBM_HTTP_Server sends SP after chunk-size
        !tok.skip(';') ||
        !ParseBws(tok) || // Bg 4492: ICAP servers send SP before chunk-ext-name
        !tok.prefix(extName, CharacterSet::TCHAR) ||
        !ParseBws(tok)) {
        tok = savedTok;
        return false;
    }

    if (!tok.skip('='))
        return true; // parsed a valueless chunk-ext

    if (!ParseBws(tok)) {
        tok = savedTok;
        return false;
    }
    // for now the only known extension belongs to the last chunk
    if (!theChunkSize && knownExtensions.find(extName) != knownExtensions.end()) {
        static const SBuf useOriginalBodyName("use-original-body");
        if (extName == useOriginalBodyName) {
            if (!parseIntExtension(tok, useOriginalBodyName, useOriginBody)) {
                tok = savedTok;
                return false;
            }
            debugs(94, 3, "found " << extName << '=' << useOriginBody);
            return true;
        }
    }

    SBuf ignoredValue;
    if (!tokenOrQuotedString(tok, ignoredValue, false)) {
        tok = savedTok;
        return false;
    }

    debugs(94, 5, "skipping unknown chunk extension " << extName);
    return true;
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

    if (skipLineTerminator(tok)) {
        buf_ = tok.remaining(); // parse checkpoint
        theChunkSize = 0; // done with the current chunk
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_SZ;
        return true;
    }

    return false;
}

