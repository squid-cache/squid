/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 74    HTTP Message */

#include "squid.h"
#include "Debug.h"
#include "http/one/Parser.h"
#include "HttpHdrCc.h"
#include "HttpHeaderTools.h"
#include "HttpMsg.h"
#include "MemBuf.h"
#include "mime_header.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

HttpMsg::HttpMsg(http_hdr_owner_type owner):
    http_ver(Http::ProtocolVersion()),
    header(owner),
    cache_control(NULL),
    hdr_sz(0),
    content_length(0),
    pstate(psReadyToParseStartLine),
    sources(0)
{}

HttpMsg::~HttpMsg()
{
    assert(!body_pipe);
}

void
HttpMsg::putCc(const HttpHdrCc *otherCc)
{
    // get rid of the old CC, if any
    if (cache_control) {
        delete cache_control;
        cache_control = nullptr;
        if (!otherCc)
            header.delById(Http::HdrType::CACHE_CONTROL);
        // else it will be deleted inside putCc() below
    }

    // add new CC, if any
    if (otherCc) {
        cache_control = new HttpHdrCc(*otherCc);
        header.putCc(cache_control);
    }
}

HttpMsgParseState &operator++ (HttpMsgParseState &aState)
{
    int tmp = (int)aState;
    aState = (HttpMsgParseState)(++tmp);
    return aState;
}

/* find end of headers */
static int
httpMsgIsolateHeaders(const char **parse_start, int l, const char **blk_start, const char **blk_end)
{
    /*
     * parse_start points to the first line of HTTP message *headers*,
     * not including the request or status lines
     */
    size_t end = headersEnd(*parse_start, l);
    int nnl;

    if (end) {
        *blk_start = *parse_start;
        *blk_end = *parse_start + end - 1;
        /*
         * leave blk_end pointing to the first character after the
         * first newline which terminates the headers
         */
        assert(**blk_end == '\n');

        while (*(*blk_end - 1) == '\r')
            --(*blk_end);

        assert(*(*blk_end - 1) == '\n');

        *parse_start += end;

        return 1;
    }

    /*
     * If we didn't find the end of headers, and parse_start does
     * NOT point to a CR or NL character, then return failure
     */
    if (**parse_start != '\r' && **parse_start != '\n')
        return 0;       /* failure */

    /*
     * If we didn't find the end of headers, and parse_start does point
     * to an empty line, then we have empty headers.  Skip all CR and
     * NL characters up to the first NL.  Leave parse_start pointing at
     * the first character after the first NL.
     */
    *blk_start = *parse_start;

    *blk_end = *blk_start;

    for (nnl = 0; nnl == 0; ++(*parse_start)) {
        if (**parse_start == '\r')
            (void) 0;
        else if (**parse_start == '\n')
            ++nnl;
        else
            break;
    }

    return 1;
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
HttpMsg::parse(const char *buf, const size_t sz, bool eof, Http::StatusCode *error)
{
    assert(error);
    *error = Http::scNone;

    // find the end of headers
    const size_t hdr_len = headersEnd(buf, sz);

    // sanity check the start line to see if this is in fact an HTTP message
    if (!sanityCheckStartLine(buf, hdr_len, error)) {
        // NP: sanityCheck sets *error and sends debug warnings on syntax errors.
        // if we have seen the connection close, this is an error too
        if (eof && *error == Http::scNone)
            *error = Http::scInvalidHeader;

        return false;
    }

    if (hdr_len > Config.maxReplyHeaderSize || (hdr_len <= 0 && sz > Config.maxReplyHeaderSize)) {
        debugs(58, DBG_IMPORTANT, "HttpMsg::parse: Too large reply header (" << hdr_len << " > " << Config.maxReplyHeaderSize);
        *error = Http::scHeaderTooLarge;
        return false;
    }

    if (hdr_len <= 0) {
        debugs(58, 3, "HttpMsg::parse: failed to find end of headers (eof: " << eof << ") in '" << buf << "'");

        if (eof) // iff we have seen the end, this is an error
            *error = Http::scInvalidHeader;

        return false;
    }

    const int res = httpMsgParseStep(buf, sz, eof);

    if (res < 0) { // error
        debugs(58, 3, "HttpMsg::parse: cannot parse isolated headers in '" << buf << "'");
        *error = Http::scInvalidHeader;
        return false;
    }

    if (res == 0) {
        debugs(58, 2, "HttpMsg::parse: strange, need more data near '" << buf << "'");
        *error = Http::scInvalidHeader;
        return false; // but this should not happen due to headersEnd() above
    }

    assert(res > 0);
    debugs(58, 9, "HttpMsg::parse success (" << hdr_len << " bytes) near '" << buf << "'");

    if (hdr_sz != (int)hdr_len) {
        debugs(58, DBG_IMPORTANT, "internal HttpMsg::parse vs. headersEnd error: " <<
               hdr_sz << " != " << hdr_len);
        hdr_sz = (int)hdr_len; // because old http.cc code used hdr_len
    }

    return true;
}

/*
 * parseCharBuf() takes character buffer of HTTP headers (buf),
 * which may not be NULL-terminated, and fills in an HttpMsg
 * structure.  The parameter 'end' specifies the offset to
 * the end of the reply headers.  The caller may know where the
 * end is, but is unable to NULL-terminate the buffer.  This function
 * returns true on success.
 */
bool
HttpMsg::parseCharBuf(const char *buf, ssize_t end)
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

/*
 * parses a 0-terminating buffer into HttpMsg.
 * Returns:
 *      1 -- success
 *       0 -- need more data (partial parse)
 *      -1 -- parse error
 */
int
HttpMsg::httpMsgParseStep(const char *buf, int len, int atEnd)
{
    const char *parse_start = buf;
    int parse_len = len;
    const char *blk_start, *blk_end;
    const char **parse_end_ptr = &blk_end;
    assert(parse_start);
    assert(pstate < psParsed);

    *parse_end_ptr = parse_start;

    PROF_start(HttpMsg_httpMsgParseStep);

    if (pstate == psReadyToParseStartLine) {
        if (!httpMsgIsolateStart(&parse_start, &blk_start, &blk_end)) {
            PROF_stop(HttpMsg_httpMsgParseStep);
            return 0;
        }

        if (!parseFirstLine(blk_start, blk_end)) {
            PROF_stop(HttpMsg_httpMsgParseStep);
            return httpMsgParseError();
        }

        *parse_end_ptr = parse_start;

        hdr_sz = *parse_end_ptr - buf;
        parse_len = parse_len - hdr_sz;

        ++pstate;
    }

    /*
     * XXX This code uses parse_start; but if we're incrementally parsing then
     * this code might not actually be given parse_start at the right spot (just
     * after headers.) Grr.
     */
    if (pstate == psReadyToParseHeaders) {
        if (!httpMsgIsolateHeaders(&parse_start, parse_len, &blk_start, &blk_end)) {
            if (atEnd) {
                blk_start = parse_start;
                blk_end = blk_start + strlen(blk_start);
            } else {
                PROF_stop(HttpMsg_httpMsgParseStep);
                return 0;
            }
        }

        if (!header.parse(blk_start, blk_end-blk_start)) {
            PROF_stop(HttpMsg_httpMsgParseStep);
            return httpMsgParseError();
        }

        hdrCacheInit();

        *parse_end_ptr = parse_start;

        hdr_sz = *parse_end_ptr - buf;

        ++pstate;
    }

    PROF_stop(HttpMsg_httpMsgParseStep);
    return 1;
}

bool
HttpMsg::parseHeader(Http1::Parser &hp)
{
    // HTTP/1 message contains "zero or more header fields"
    // zero does not need parsing
    // XXX: c_str() reallocates. performance regression.
    if (hp.headerBlockSize() && !header.parse(hp.mimeHeader().c_str(), hp.headerBlockSize())) {
        pstate = psError;
        return false;
    }

    // XXX: we are just parsing HTTP headers, not the whole message prefix here
    hdr_sz = hp.messageHeaderSize();
    pstate = psParsed;
    hdrCacheInit();
    return true;
}

/* handy: resets and returns -1 */
int
HttpMsg::httpMsgParseError()
{
    reset();
    return -1;
}

void
HttpMsg::setContentLength(int64_t clen)
{
    header.delById(Http::HdrType::CONTENT_LENGTH); // if any
    header.putInt64(Http::HdrType::CONTENT_LENGTH, clen);
    content_length = clen;
}

bool
HttpMsg::persistent() const
{
    if (http_ver > Http::ProtocolVersion(1,0)) {
        /*
         * for modern versions of HTTP: persistent unless there is
         * a "Connection: close" header.
         */
        return !httpHeaderHasConnDir(&header, "close");
    } else {
        /* for old versions of HTTP: persistent if has "keep-alive" */
        return httpHeaderHasConnDir(&header, "keep-alive");
    }
}

void HttpMsg::packInto(Packable *p, bool full_uri) const
{
    packFirstLineInto(p, full_uri);
    header.packInto(p);
    p->append("\r\n", 2);
}

void HttpMsg::hdrCacheInit()
{
    content_length = header.getInt64(Http::HdrType::CONTENT_LENGTH);
    assert(NULL == cache_control);
    cache_control = header.getCc();
}

/*
 * useful for debugging
 */
void HttpMsg::firstLineBuf(MemBuf& mb)
{
    packFirstLineInto(&mb, true);
}

