/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTPPARSER_H
#define _SQUID_SRC_HTTPPARSER_H

#include "http/StatusCode.h"

// Parser states
#define HTTP_PARSE_NONE   0 // nothing. completely unset state.
#define HTTP_PARSE_NEW    1 // initialized, but nothing usefully parsed yet.

/** HTTP protocol parser.
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * either an error state or, an HTTP procotol request major segments:
 *  1. Request Line (method, URL, protocol, version)
 *  2. Mime header block
 */
class HttpParser
{
public:
    HttpParser() { clear(); }

    /** Initialize a new parser.
     * Presenting it a buffer to work on and the current length of available
     * data.
     * NOTE: This is *not* the buffer size, just the parse-able data length.
     * The parse routines may be called again later with more data.
     */
    HttpParser(const char *aBuf, int len) { reset(aBuf,len); };

    /// Set this parser back to a default state.
    /// Will DROP any reference to a buffer (does not free).
    void clear();

    /// Reset the parser for use on a new buffer.
    void reset(const char *aBuf, int len);

    /**
     * Attempt to parse the first line of a new request message.
     *
     * Governed by:
     *  RFC 1945 section 5.1
     *  RFC 2616 section 5.1
     *
     * Parsing state is stored between calls. However the current implementation
     * begins parsing from scratch on every call.
     * The return value tells you whether the parsing state fields are valid or not.
     *
     * \retval -1  an error occurred. request_parse_status indicates HTTP status result.
     * \retval  1  successful parse. member fields contain the request-line items
     * \retval  0  more data is needed to complete the parse
     */
    int parseRequestFirstLine();

public:
    uint8_t state;
    const char *buf;
    int bufsiz;

    /// Offsets for pieces of the (HTTP request) Request-Line as per RFC 2616
    struct request_offsets {
        int start, end;
        int m_start, m_end; // method
        int u_start, u_end; // url
        int v_start, v_end; // version (full text)
        int v_maj, v_min;   // version numerics
    } req;

    // Offsets for pieces of the MiME Header segment
    int hdr_start, hdr_end;

    // TODO: Offsets for pieces of the (HTTP reply) Status-Line as per RFC 2616

    /** HTTP status code to be used on the invalid-request error page
     * Http::scNone indicates incomplete parse, Http::scOkay indicates no error.
     */
    Http::StatusCode request_parse_status;
};

// Legacy functions
#define HttpParserInit(h,b,l) (h)->reset((b),(l))
int HttpParserParseReqLine(HttpParser *hp);

#define MSGDODEBUG 0
#if MSGDODEBUG
int HttpParserReqSz(HttpParser *);
int HttpParserHdrSz(HttpParser *);
const char * HttpParserHdrBuf(HttpParser *);
int HttpParserRequestLen(HttpParser *hp);
#else
#define HttpParserReqSz(hp)     ( (hp)->req.end - (hp)->req.start + 1 )
#define HttpParserHdrSz(hp)     ( (hp)->hdr_end - (hp)->hdr_start + 1 )
#define HttpParserHdrBuf(hp)    ( (hp)->buf + (hp)->hdr_start )
#define HttpParserRequestLen(hp)        ( (hp)->hdr_end - (hp)->req.start + 1 )
#endif

#endif /*  _SQUID_SRC_HTTPPARSER_H */

