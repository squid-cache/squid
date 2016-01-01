/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CHUNKEDCODINGPARSER_H
#define SQUID_CHUNKEDCODINGPARSER_H

class MemBuf;

/**
 \ingroup ChunkEncodingAPI Chunked Encoding API
 \par
 * ChunkedCodingParser is an incremental parser for chunked transfer coding
 * used by HTTP and ICAP. The parser shovels content bytes from the raw
 * input buffer into the content output buffer, both caller-supplied.
 * Ignores chunk extensions except for ICAP's ieof.
 * Has a trailer-handling placeholder.
 */
class ChunkedCodingParser
{

public:
    ChunkedCodingParser();

    void reset();

    /**
     \retval true    complete success
     \retval false   needs more data
     \throws ??      error.
     */
    bool parse(MemBuf *rawData, MemBuf *parsedContent);

    bool needsMoreData() const;
    bool needsMoreSpace() const;

private:
    typedef void (ChunkedCodingParser::*Step)();

private:
    bool mayContinue() const;

    void parseChunkSize();
    void parseUnusedChunkExtension();
    void parseLastChunkExtension();
    void parseChunkBeg();
    void parseChunkBody();
    void parseChunkEnd();
    void parseTrailer();
    void parseTrailerHeader();
    void parseMessageEnd();

    bool findCrlf(size_t &crlfBeg, size_t &crlfEnd);
    bool findCrlf(size_t &crlfBeg, size_t &crlfEnd, bool &quoted, bool &slashed);

private:
    static Step psChunkSize;
    static Step psUnusedChunkExtension;
    static Step psLastChunkExtension;
    static Step psChunkBody;
    static Step psChunkEnd;
    static Step psTrailer;
    static Step psMessageEnd;

    MemBuf *theIn;
    MemBuf *theOut;

    Step theStep;
    uint64_t theChunkSize;
    uint64_t theLeftBodySize;
    bool doNeedMoreData;
    bool inQuoted; ///< stores parsing state for incremental findCrlf
    bool inSlashed; ///< stores parsing state for incremental findCrlf

public:
    int64_t useOriginBody;
};

#endif /* SQUID_CHUNKEDCODINGPARSER_H */

