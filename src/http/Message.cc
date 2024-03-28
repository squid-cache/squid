/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 74    HTTP Message */

#include "squid.h"
#include "debug/Stream.h"
#include "http/ContentLengthInterpreter.h"
#include "http/Message.h"
#include "http/one/Parser.h"
#include "HttpHdrCc.h"
#include "HttpHeaderTools.h"
#include "MemBuf.h"
#include "mime_header.h"
#include "SquidConfig.h"

Http::Message::Message(http_hdr_owner_type owner):
    http_ver(Http::ProtocolVersion()),
    header(owner)
{}

Http::Message::~Message()
{
    assert(!body_pipe);
}

void
Http::Message::putCc(const HttpHdrCc &otherCc)
{
    delete cache_control;
    cache_control = new HttpHdrCc(otherCc);
    header.putCc(*cache_control);
}

/* find first CRLF */
static int
httpMsgIsolateStart(const char **parse_start, const char **blk_start, const char **blk_end)
{
    int slen = strcspn(*parse_start, "\r\n");

    if (!(*parse_start)[slen])  /* no CRLF found */
        return 0;

    *blk_start = *parse_start;

    *blk_end = *blk_start + slen;

    while (**blk_end == '\r')   /* CR */
        ++(*blk_end);

    if (**blk_end == '\n')      /* LF */
        ++(*blk_end);

    *parse_start = *blk_end;

    return 1;
}

// negative return is the negated Http::StatusCode error code
// zero return means need more data
// positive return is the size of parsed headers
bool
Http::Message::parse(const char *buf, const size_t sz, bool eof, Http::StatusCode *error)
{
    assert(error);
    *error = Http::scNone;

    // find the end of headers
    const size_t hdr_len = headersEnd(buf, sz);

    if (hdr_len > Config.maxReplyHeaderSize || (hdr_len == 0 && sz > Config.maxReplyHeaderSize)) {
        debugs(58, 3, "input too large: " << hdr_len << " or " << sz << " > " << Config.maxReplyHeaderSize);
        *error = Http::scHeaderTooLarge;
        return false;
    }

    // sanity check the start line to see if this is in fact an HTTP message
    if (!sanityCheckStartLine(buf, hdr_len, error)) {
        // NP: sanityCheck sets *error and sends debug warnings on syntax errors.
        // if we have seen the connection close, this is an error too
        if (eof && *error == Http::scNone)
            *error = Http::scInvalidHeader;

        return false;
    }

    assert(hdr_len > 0); // sanityCheckStartLine() rejects buffers that cannot be parsed

    const int res = httpMsgParseStep(buf, sz, eof);

    if (res < 0) { // error
        debugs(58, 3, "cannot parse isolated headers in '" << buf << "'");
        *error = Http::scInvalidHeader;
        return false;
    }

    if (res == 0) {
        debugs(58, 2, "strange, need more data near '" << buf << "'");
        *error = Http::scInvalidHeader;
        return false; // but this should not happen due to headersEnd() above
    }

    assert(res > 0);
    debugs(58, 9, "success (" << hdr_len << " bytes) near '" << buf << "'");

    if (hdr_sz != (int)hdr_len) {
        debugs(58, DBG_IMPORTANT, "ERROR: internal Http::Message::parse vs. headersEnd failure: " <<
               hdr_sz << " != " << hdr_len);
        hdr_sz = (int)hdr_len; // because old http.cc code used hdr_len
    }

    return true;
}

/**
 * parseCharBuf() takes character buffer of HTTP headers (buf),
 * which may not be NULL-terminated, and fills in an Http::Message
 * structure.  The parameter 'end' specifies the offset to
 * the end of the reply headers.  The caller may know where the
 * end is, but is unable to NULL-terminate the buffer.  This function
 * returns true on success.
 */
bool
Http::Message::parseCharBuf(const char *buf, ssize_t end)
{
    MemBuf mb;
    int success;
    /* reset current state, because we are not used in incremental fashion */
    reset();
    mb.init();
    mb.append(buf, end);
    mb.terminate();
    success = httpMsgParseStep(mb.buf, mb.size, 0);
    mb.clean();
    return success == 1;
}

/**
 * parses a 0-terminated buffer into Http::Message.
 *
 * \retval  1 success
 * \retval  0 need more data (partial parse)
 * \retval -1 parse error
 */
int
Http::Message::httpMsgParseStep(const char *buf, int len, int atEnd)
{
    const char *parse_start = buf;
    int parse_len = len;
    const char *blk_start, *blk_end;
    const char **parse_end_ptr = &blk_end;
    assert(parse_start);
    assert(pstate < Http::Message::psParsed);

    *parse_end_ptr = parse_start;

    if (pstate == Http::Message::psReadyToParseStartLine) {
        if (!httpMsgIsolateStart(&parse_start, &blk_start, &blk_end)) {
            return 0;
        }

        if (!parseFirstLine(blk_start, blk_end)) {
            return httpMsgParseError();
        }

        *parse_end_ptr = parse_start;

        hdr_sz = *parse_end_ptr - buf;
        parse_len = parse_len - hdr_sz;

        pstate = Http::Message::psReadyToParseHeaders;
    }

    /*
     * XXX This code uses parse_start; but if we're incrementally parsing then
     * this code might not actually be given parse_start at the right spot (just
     * after headers.) Grr.
     */
    if (pstate == Http::Message::psReadyToParseHeaders) {
        size_t hsize = 0;
        Http::ContentLengthInterpreter interpreter;
        configureContentLengthInterpreter(interpreter);
        const int parsed = header.parse(parse_start, parse_len, atEnd, hsize, interpreter);
        if (parsed <= 0) {
            return !parsed ? 0 : httpMsgParseError();
        }
        hdr_sz += hsize;
        hdrCacheInit();
        pstate = Http::Message::psParsed;
    }

    return 1;
}

bool
Http::Message::parseHeader(Http1::Parser &hp, Http::ContentLengthInterpreter &clen)
{
    // HTTP/1 message contains "zero or more header fields"
    // zero does not need parsing
    // XXX: c_str() reallocates. performance regression.
    configureContentLengthInterpreter(clen);
    if (hp.headerBlockSize() && !header.parse(hp.mimeHeader().c_str(), hp.headerBlockSize(), clen)) {
        pstate = Http::Message::psError;
        return false;
    }

    // XXX: we are just parsing HTTP headers, not the whole message prefix here
    hdr_sz = hp.messageHeaderSize();
    pstate = Http::Message::psParsed;
    hdrCacheInit();
    return true;
}

/* handy: resets and returns -1 */
int
Http::Message::httpMsgParseError()
{
    reset();
    return -1;
}

void
Http::Message::setContentLength(int64_t clen)
{
    header.delById(Http::HdrType::CONTENT_LENGTH); // if any
    header.putInt64(Http::HdrType::CONTENT_LENGTH, clen);
    content_length = clen;
}

bool
Http::Message::persistent() const
{
    if (http_ver > Http::ProtocolVersion(1,0)) {
        /*
         * for modern versions of HTTP: persistent unless there is
         * a "Connection: close" header.
         */
        static SBuf close("close", 5);
        return !httpHeaderHasConnDir(&header, close);
    } else {
        /* for old versions of HTTP: persistent if has "keep-alive" */
        static SBuf keepAlive("keep-alive", 10);
        return httpHeaderHasConnDir(&header, keepAlive);
    }
}

void
Http::Message::packInto(Packable *p, bool full_uri) const
{
    packFirstLineInto(p, full_uri);
    header.packInto(p);
    p->append("\r\n", 2);
}

void
Http::Message::hdrCacheInit()
{
    content_length = header.getInt64(Http::HdrType::CONTENT_LENGTH);
    assert(nullptr == cache_control);
    cache_control = header.getCc();
}

/// useful for debugging
void
Http::Message::firstLineBuf(MemBuf &mb)
{
    packFirstLineInto(&mb, true);
}

