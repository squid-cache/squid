
/*
 * $Id: ChunkedCodingParser.h,v 1.1 2007/12/26 22:33:32 hno Exp $
 * 
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_CHUNKEDCODINGPARSER_H
#define SQUID_CHUNKEDCODINGPARSER_H

#include "RefCount.h"

// ChunkedCodingParser is an incremental parser for chunked transfer coding
// used by HTTP and ICAP. The parser shovels content bytes from the raw
// input buffer into the content output buffer, both caller-supplied.
// Ignores chunk extensions except for ICAP's ieof.
// Has a trailer-handling placeholder.

class ChunkedCodingParser
{

public:
    ChunkedCodingParser();

    void reset();

    // true = complete success; false == needs more data
    bool parse(MemBuf *rawData, MemBuf *parsedContent); // throws on error

    bool needsMoreData() const;
    bool needsMoreSpace() const;

private:
    typedef void (ChunkedCodingParser::*Step)();

private:
    bool mayContinue() const;

    void parseChunkBeg();
    void parseChunkBody();
    void parseChunkEnd();
    void parseTrailer();
    void parseTrailerHeader();
    void parseMessageEnd();

    bool findCrlf(size_t &crlfBeg, size_t &crlfEnd);

private:
    static Step psChunkBeg;
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
};

#endif /* SQUID_CHUNKEDCODINGPARSER_H */
