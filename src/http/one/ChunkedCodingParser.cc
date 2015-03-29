/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "http/one/ChunkedCodingParser.h"
#include "http/ProtocolVersion.h"
#include "MemBuf.h"
#include "Parsing.h"

Http::One::ChunkedCodingParser::ChunkedCodingParser()
{
    // chunked encoding only exists in HTTP/1.1
    Http1::Parser::msgProtocol_ = Http::ProtocolVersion(1,1);

    clear();
}

void
Http::One::ChunkedCodingParser::clear()
{
    parsingStage_ = Http1::HTTP_PARSE_NONE;
    theChunkSize = theLeftBodySize = 0;
    theIn = theOut = NULL;
    useOriginBody = -1;
    inQuoted = inSlashed = false;
}

bool
Http::One::ChunkedCodingParser::parse(MemBuf *rawData, MemBuf *parsedContent)
{
    Must(rawData && parsedContent);
    theIn = rawData;
    theOut = parsedContent;

    if (parsingStage_ == Http1::HTTP_PARSE_NONE)
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_SZ;

    // loop for as many chunks as we can
    // use do-while instead of while so that we can incrementally
    // restart in the middle of a chunk/frame
    do {

        if (parsingStage_ == Http1::HTTP_PARSE_CHUNK_EXT) {
            if (theChunkSize)
                parseUnusedChunkExtension();
            else
                parseLastChunkExtension();
        }

        if (parsingStage_ == Http1::HTTP_PARSE_CHUNK && !parseChunkBody())
            return false;

        if (parsingStage_ == Http1::HTTP_PARSE_MIME && !parseTrailer())
            return false;

        // loop for as many chunks as we can
    } while (parsingStage_ == Http1::HTTP_PARSE_CHUNK_SZ && parseChunkSize());

    return !needsMoreData() && !needsMoreSpace();
}

bool
Http::One::ChunkedCodingParser::needsMoreSpace() const
{
    assert(theOut);
    return parsingStage_ == Http1::HTTP_PARSE_CHUNK && !theOut->hasPotentialSpace();
}

bool
Http::One::ChunkedCodingParser::parseChunkSize()
{
    Must(theChunkSize <= 0); // Should(), really

    const char *p = theIn->content();
    while (p < theIn->space() && xisxdigit(*p)) ++p;
    if (p >= theIn->space()) {
        return false;
    }

    int64_t size = -1;
    if (StringToInt64(theIn->content(), size, &p, 16)) {
        if (size < 0)
            throw TexcHere("negative chunk size");

        theChunkSize = theLeftBodySize = size;
        debugs(94,7, "found chunk: " << theChunkSize);
        theIn->consume(p - theIn->content());
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_EXT;
        return true;
    } else
        throw TexcHere("corrupted chunk size");

    return false;
}

/// Skips a set of RFC 7230 section 4.1.1 chunk-ext
/// http://tools.ietf.org/html/rfc7230#section-4.1.1
void
Http::One::ChunkedCodingParser::parseUnusedChunkExtension()
{
    size_t crlfBeg = 0;
    size_t crlfEnd = 0;
    if (findCrlf(crlfBeg, crlfEnd, inQuoted, inSlashed)) {
        inQuoted = inSlashed = false;
        theIn->consume(crlfEnd);
        // non-0 chunk means data, 0-size means optional Trailer follows
        parsingStage_ = theChunkSize ? Http1::HTTP_PARSE_CHUNK : Http1::HTTP_PARSE_MIME;
    } else {
        theIn->consume(theIn->contentSize());
    }
}

bool
Http::One::ChunkedCodingParser::parseChunkBody()
{
    Must(theLeftBodySize > 0); // Should, really

    const size_t availSize = min(theLeftBodySize, (uint64_t)theIn->contentSize());
    const size_t safeSize = min(availSize, (size_t)theOut->potentialSpaceSize());

    theOut->append(theIn->content(), safeSize);
    theIn->consume(safeSize);
    theLeftBodySize -= safeSize;

    if (theLeftBodySize == 0)
        return parseChunkEnd();
    else
        Must(needsMoreData() || needsMoreSpace());

    return true;
}

bool
Http::One::ChunkedCodingParser::parseChunkEnd()
{
    Must(theLeftBodySize == 0); // Should(), really

    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (findCrlf(crlfBeg, crlfEnd)) {
        if (crlfBeg != 0) {
            throw TexcHere("found data between chunk end and CRLF");
            return false;
        }

        theIn->consume(crlfEnd);
        theChunkSize = 0; // done with the current chunk
        parsingStage_ = Http1::HTTP_PARSE_CHUNK_SZ;
        return true;
    }

    return false;
}

/**
 * Parse Trailer RFC 7230 section 4.1.2 trailer-part
 * http://tools.ietf.org/html/rfc7230#section-4.1.2
 *
 * trailer-part   = *( header-field CRLF )
 *
 * Currently Trailer headers are ignored/skipped
 */
bool
Http::One::ChunkedCodingParser::parseTrailer()
{
    Must(theChunkSize == 0); // Should(), really

    while (parsingStage_ == Http1::HTTP_PARSE_MIME) {
        if (!parseTrailerHeader())
            return false;
    }

    return true;
}

/// skip one RFC 7230 header-field from theIn buffer
bool
Http::One::ChunkedCodingParser::parseTrailerHeader()
{
    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (findCrlf(crlfBeg, crlfEnd)) {

#if TRAILERS_ARE_SUPPORTED
        if (crlfBeg > 0)
            theTrailer.append(theIn->content(), crlfEnd);
#endif

        theIn->consume(crlfEnd);

        if (crlfBeg == 0) {
            parsingStage_ = Http1::HTTP_PARSE_DONE;
        }

        return true;
    }

     return false;
}

/// Finds next CRLF. Does not store parsing state.
bool
Http::One::ChunkedCodingParser::findCrlf(size_t &crlfBeg, size_t &crlfEnd)
{
    bool quoted = false;
    bool slashed = false;
    return findCrlf(crlfBeg, crlfEnd, quoted, slashed);
}

/// Finds next CRLF. Parsing state stored in quoted and slashed
/// parameters. Incremental: can resume when more data is available.
bool
Http::One::ChunkedCodingParser::findCrlf(size_t &crlfBeg, size_t &crlfEnd, bool &quoted, bool &slashed)
{
    // XXX: This code was copied, with permission, from another software.
    // There is a similar and probably better code inside httpHeaderParse
    // but it seems difficult to isolate due to parsing-unrelated bloat.
    // Such isolation should probably be done before this class is used
    // for handling of traffic "more external" than ICAP.

    const char *buf = theIn->content();
    size_t size = theIn->contentSize();

    ssize_t crOff = -1;

    for (size_t i = 0; i < size; ++i) {
        if (slashed) {
            slashed = false;
            continue;
        }

        const char c = buf[i];

        // handle quoted strings
        if (quoted) {
            if (c == '\\')
                slashed = true;
            else if (c == '"')
                quoted = false;

            continue;
        } else if (c == '"') {
            quoted = true;
            crOff = -1;
            continue;
        }

        if (crOff < 0) { // looking for the first CR or LF

            if (c == '\n') {
                crlfBeg = i;
                crlfEnd = ++i;
                return true;
            }

            if (c == '\r')
                crOff = i;
        } else { // skipping CRs, looking for the first LF

            if (c == '\n') {
                crlfBeg = crOff;
                crlfEnd = ++i;
                return true;
            }

            if (c != '\r')
                crOff = -1;
        }
    }

    return false;
}

/**
 * Parses a set of RFC 7230 section 4.1.1 chunk-ext
 * http://tools.ietf.org/html/rfc7230#section-4.1.1
 *
 *  chunk-ext      = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
 *  chunk-ext-name = token
 *  chunk-ext-val  = token / quoted-string
 *
 * ICAP 'use-original-body=N' extension is supported.
 */
void
Http::One::ChunkedCodingParser::parseLastChunkExtension()
{
    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (!findCrlf(crlfBeg, crlfEnd))
        return;

    const char *const startExt = theIn->content();
    const char *const endExt = theIn->content() + crlfBeg;

    // chunk-extension starts at startExt and ends with LF at endEx
    for (const char *p = startExt; p < endExt;) {

        while (*p == ' ' || *p == '\t') ++p; // skip spaces before ';'

        if (*p++ != ';') // each ext name=value pair is preceded with ';'
            break;

        while (*p == ' ' || *p == '\t') ++p; // skip spaces before name

        if (p >= endExt)
            break; // malformed extension: ';' without ext name=value pair

        const int extSize = endExt - p;
        // TODO: we need debugData() stream manipulator to dump data
        debugs(94,7, "Found chunk extension; size=" << extSize);

        // TODO: support implied *LWS around '='
        if (extSize > 18 && strncmp(p, "use-original-body=", 18) == 0) {
            (void)StringToInt64(p+18, useOriginBody, &p, 10);
            debugs(94, 3, HERE << "use-original-body=" << useOriginBody);
            break; // remove to support more than just use-original-body
        } else {
            debugs(94, 5, HERE << "skipping unknown chunk extension");
            // TODO: support quoted-string chunk-ext-val
            while (p < endExt && *p != ';') ++p; // skip until the next ';'
        }
    }

    theIn->consume(crlfEnd);

    parsingStage_ = theChunkSize ? Http1::HTTP_PARSE_CHUNK : Http1::HTTP_PARSE_MIME;
}

