#include "squid.h"
#include "base/TextException.h"
#include "Parsing.h"
#include "ChunkedCodingParser.h"
#include "MemBuf.h"

ChunkedCodingParser::Step ChunkedCodingParser::psChunkBeg = &ChunkedCodingParser::parseChunkBeg;
ChunkedCodingParser::Step ChunkedCodingParser::psChunkBody = &ChunkedCodingParser::parseChunkBody;
ChunkedCodingParser::Step ChunkedCodingParser::psChunkEnd = &ChunkedCodingParser::parseChunkEnd;
ChunkedCodingParser::Step ChunkedCodingParser::psTrailer = &ChunkedCodingParser::parseTrailer;
ChunkedCodingParser::Step ChunkedCodingParser::psMessageEnd = &ChunkedCodingParser::parseMessageEnd;

ChunkedCodingParser::ChunkedCodingParser()
{
    reset();
}

void ChunkedCodingParser::reset()
{
    theStep = psChunkBeg;
    theChunkSize = theLeftBodySize = 0;
    doNeedMoreData = false;
    theIn = theOut = NULL;
    useOriginBody = -1;
}

bool ChunkedCodingParser::parse(MemBuf *rawData, MemBuf *parsedContent)
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

bool ChunkedCodingParser::needsMoreData() const
{
    return doNeedMoreData;
}

bool ChunkedCodingParser::needsMoreSpace() const
{
    assert(theOut);
    return theStep == psChunkBody && !theOut->hasPotentialSpace();
}

bool ChunkedCodingParser::mayContinue() const
{
    return !needsMoreData() && !needsMoreSpace() && theStep != psMessageEnd;
}

void ChunkedCodingParser::parseChunkBeg()
{
    Must(theChunkSize <= 0); // Should(), really

    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (findCrlf(crlfBeg, crlfEnd)) {
        debugs(94,7, "found chunk-size end: " << crlfBeg << "-" << crlfEnd);
        int64_t size = -1;
        const char *p = 0;

        if (StringToInt64(theIn->content(), size, &p, 16)) {
            if (size < 0) {
                throw TexcHere("negative chunk size");
                return;
            }

            // to allow chunk extensions in any chunk, remove this size check
            if (size == 0) // is this the last-chunk?
                parseChunkExtension(p, theIn->content() + crlfBeg);

            theIn->consume(crlfEnd);
            theChunkSize = theLeftBodySize = size;
            debugs(94,7, "found chunk: " << theChunkSize);
            theStep = theChunkSize == 0 ? psTrailer : psChunkBody;
            return;
        }

        throw TexcHere("corrupted chunk size");
    }

    doNeedMoreData = true;
}

void ChunkedCodingParser::parseChunkBody()
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

void ChunkedCodingParser::parseChunkEnd()
{
    Must(theLeftBodySize == 0); // Should(), really

    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (findCrlf(crlfBeg, crlfEnd)) {
        if (crlfBeg != 0) {
            throw TexcHere("found data bewteen chunk end and CRLF");
            return;
        }

        theIn->consume(crlfEnd);
        theChunkSize = 0; // done with the current chunk
        theStep = psChunkBeg;
        return;
    }

    doNeedMoreData = true;
}

void ChunkedCodingParser::parseTrailer()
{
    Must(theChunkSize == 0); // Should(), really

    while (mayContinue())
        parseTrailerHeader();
}

void ChunkedCodingParser::parseTrailerHeader()
{
    size_t crlfBeg = 0;
    size_t crlfEnd = 0;

    if (findCrlf(crlfBeg, crlfEnd)) {
        if (crlfBeg > 0)

            ; //theTrailer.append(theIn->content(), crlfEnd);

        theIn->consume(crlfEnd);

        if (crlfBeg == 0)
            theStep = psMessageEnd;

        return;
    }

    doNeedMoreData = true;
}

void ChunkedCodingParser::parseMessageEnd()
{
    // termination step, should not be called
    Must(false); // Should(), really
}

// finds next CRLF
bool ChunkedCodingParser::findCrlf(size_t &crlfBeg, size_t &crlfEnd)
{
    // XXX: This code was copied, with permission, from another software.
    // There is a similar and probably better code inside httpHeaderParse
    // but it seems difficult to isolate due to parsing-unrelated bloat.
    // Such isolation should probably be done before this class is used
    // for handling of traffic "more external" than ICAP.

    const char *buf = theIn->content();
    size_t size = theIn->contentSize();

    ssize_t crOff = -1;
    bool quoted = false;
    bool slashed = false;

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
void ChunkedCodingParser::parseChunkExtension(const char *startExt, const char *endExt)
{
    // chunk-extension starts at startExt and ends with LF at endEx
    for (const char *p = startExt; p < endExt;) {

        while (*p == ' ' || *p == '\t') ++p; // skip spaces before ';'

        if (*p++ != ';') // each ext name=value pair is preceded with ';'
            return;

        while (*p == ' ' || *p == '\t') ++p; // skip spaces before name

        if (p >= endExt)
            return; // malformed extension: ';' without ext name=value pair

        const int extSize = endExt - p;
        // TODO: we need debugData() stream manipulator to dump data
        debugs(94,7, "Found chunk extension; size=" << extSize);

        // TODO: support implied *LWS around '='
        if (extSize > 18 && strncmp(p, "use-original-body=", 18) == 0) {
            (void)StringToInt64(p+18, useOriginBody, &p, 10);
            debugs(94, 3, HERE << "use-original-body=" << useOriginBody);
            return; // remove to support more than just use-original-body
        } else {
            debugs(94, 5, HERE << "skipping unknown chunk extension");
            // TODO: support quoted-string chunk-ext-val
            while (p < endExt && *p != ';') ++p; // skip until the next ';'
        }
    }
}
