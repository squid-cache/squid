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
#include "MemBuf.h"
#include "Parsing.h"

Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psChunkSize = &Http::One::ChunkedCodingParser::parseChunkSize;
Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psUnusedChunkExtension = &Http::One::ChunkedCodingParser::parseUnusedChunkExtension;
Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psLastChunkExtension = &Http::One::ChunkedCodingParser::parseLastChunkExtension;
Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psChunkBody = &Http::One::ChunkedCodingParser::parseChunkBody;
Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psChunkEnd = &Http::One::ChunkedCodingParser::parseChunkEnd;
Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psTrailer = &Http::One::ChunkedCodingParser::parseTrailer;
Http::One::ChunkedCodingParser::Step Http::One::ChunkedCodingParser::psMessageEnd = &Http::One::ChunkedCodingParser::parseMessageEnd;

Http::One::ChunkedCodingParser::ChunkedCodingParser()
{
    reset();
}

void
Http::One::ChunkedCodingParser::reset()
{
    theStep = psChunkSize;
    theChunkSize = theLeftBodySize = 0;
    doNeedMoreData = false;
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

    // we must reset this all the time so that mayContinue() lets us
    // output more content if we stopped due to needsMoreSpace() before
    doNeedMoreData = !theIn->hasContent();

    while (mayContinue()) {
        (this->*theStep)();
    }

    return theStep == psMessageEnd;
}

bool
Http::One::ChunkedCodingParser::needsMoreData() const
{
    return doNeedMoreData;
}

bool
Http::One::ChunkedCodingParser::needsMoreSpace() const
{
    assert(theOut);
    return theStep == psChunkBody && !theOut->hasPotentialSpace();
}

bool
Http::One::ChunkedCodingParser::mayContinue() const
{
    return !needsMoreData() && !needsMoreSpace() && theStep != psMessageEnd;
}

void
Http::One::ChunkedCodingParser::parseChunkSize()
{
    Must(theChunkSize <= 0); // Should(), really

    const char *p = theIn->content();
    while (p < theIn->space() && xisxdigit(*p)) ++p;
    if (p >= theIn->space()) {
        doNeedMoreData = true;
        return;
    }

    int64_t size = -1;
    if (StringToInt64(theIn->content(), size, &p, 16)) {
        if (size < 0)
            throw TexcHere("negative chunk size");

        theChunkSize = theLeftBodySize = size;
        debugs(94,7, "found chunk: " << theChunkSize);
        // parse chunk extensions only in the last-chunk
        if (theChunkSize)
            theStep = psUnusedChunkExtension;
        else {
            theIn->consume(p - theIn->content());
            theStep = psLastChunkExtension;
        }
    } else
        throw TexcHere("corrupted chunk size");
}

void
Http::One::ChunkedCodingParser::parseUnusedChunkExtension()
{
    size_t crlfBeg = 0;
    size_t crlfEnd = 0;
    if (findCrlf(crlfBeg, crlfEnd, inQuoted, inSlashed)) {
        inQuoted = inSlashed = false;
        theIn->consume(crlfEnd);
        theStep = theChunkSize ? psChunkBody : psTrailer;
    } else {
        theIn->consume(theIn->contentSize());
        doNeedMoreData = true;
    }
}

void
Http::One::ChunkedCodingParser::parseChunkBody()
{
    Must(theLeftBodySize > 0); // Should, really

    const size_t availSize = min(theLeftBodySize, (uint64_t)theIn->contentSize());
    const size_t safeSize = min(availSize, (size_t)theOut->potentialSpaceSize());

    doNeedMoreData = availSize < theLeftBodySize;
    // and we may also need more space

    theOut->append(theIn->content(), safeSize);
    theIn->consume(safeSize);
    theLeftBodySize -= safeSize;

    if (theLeftBodySize == 0)
        theStep = psChunkEnd;
    else
        Must(needsMoreData() || needsMoreSpace());
}

void
Http::One::ChunkedCodingParser::parseChunkEnd()
{
    Must(theLeftBodySize == 0); // Should(), really

    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (findCrlf(crlfBeg, crlfEnd)) {
        if (crlfBeg != 0) {
            throw TexcHere("found data between chunk end and CRLF");
            return;
        }

        theIn->consume(crlfEnd);
        theChunkSize = 0; // done with the current chunk
        theStep = psChunkSize;
        return;
    }

    doNeedMoreData = true;
}

void
Http::One::ChunkedCodingParser::parseTrailer()
{
    Must(theChunkSize == 0); // Should(), really

    while (mayContinue())
        parseTrailerHeader();
}

void
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

        if (crlfBeg == 0)
            theStep = psMessageEnd;

        return;
    }

    doNeedMoreData = true;
}

void
Http::One::ChunkedCodingParser::parseMessageEnd()
{
    // termination step, should not be called
    Must(false); // Should(), really
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

// chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
void
Http::One::ChunkedCodingParser::parseLastChunkExtension()
{
    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (!findCrlf(crlfBeg, crlfEnd)) {
        doNeedMoreData = true;
        return;
    }

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
    theStep = theChunkSize ? psChunkBody : psTrailer;
}

