
/*
 * $Id$
 *
 * DEBUG: section 74    HTTP Message
 * AUTHOR: Alex Rousskov
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

#include "squid.h"
#include "HttpMsg.h"
#include "MemBuf.h"

HttpMsg::HttpMsg(http_hdr_owner_type owner): header(owner),
        cache_control(NULL), hdr_sz(0), content_length(0), protocol(PROTO_NONE),
        pstate(psReadyToParseStartLine), lock_count(0)
{}

HttpMsg::~HttpMsg()
{
    assert(lock_count == 0);
    assert(!body_pipe);
}

HttpMsgParseState &operator++ (HttpMsgParseState &aState)
{
    int tmp = (int)aState;
    aState = (HttpMsgParseState)(++tmp);
    return aState;
}

/* find end of headers */
int
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
            (*blk_end)--;

        assert(*(*blk_end - 1) == '\n');

        *parse_start += end;

        return 1;
    }

    /*
     * If we didn't find the end of headers, and parse_start does
     * NOT point to a CR or NL character, then return failure
     */
    if (**parse_start != '\r' && **parse_start != '\n')
        return 0;		/* failure */

    /*
     * If we didn't find the end of headers, and parse_start does point
     * to an empty line, then we have empty headers.  Skip all CR and
     * NL characters up to the first NL.  Leave parse_start pointing at
     * the first character after the first NL.
     */
    *blk_start = *parse_start;

    *blk_end = *blk_start;

    for (nnl = 0; nnl == 0; (*parse_start)++) {
        if (**parse_start == '\r')
            (void) 0;
        else if (**parse_start == '\n')
            nnl++;
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
        (*blk_end)++;

    if (**blk_end == '\n')      /* LF */
        (*blk_end)++;

    *parse_start = *blk_end;

    return 1;
}

// negative return is the negated HTTP_ error code
// zero return means need more data
// positive return is the size of parsed headers
bool HttpMsg::parse(MemBuf *buf, bool eof, http_status *error)
{
    assert(error);
    *error = HTTP_STATUS_NONE;

    // httpMsgParseStep() and debugging require 0-termination, unfortunately
    buf->terminate(); // does not affect content size

    // find the end of headers
    const size_t hdr_len = headersEnd(buf->content(), buf->contentSize());

    // sanity check the start line to see if this is in fact an HTTP message
    if (!sanityCheckStartLine(buf, hdr_len, error)) {
        // NP: sanityCheck sets *error and sends debug warnings on syntax errors.
        // if we have seen the connection close, this is an error too
        if (eof && *error==HTTP_STATUS_NONE)
            *error = HTTP_INVALID_HEADER;

        return false;
    }

    // TODO: move to httpReplyParseStep()
    if (hdr_len > Config.maxReplyHeaderSize || (hdr_len <= 0 && (size_t)buf->contentSize() > Config.maxReplyHeaderSize)) {
        debugs(58, 1, "HttpMsg::parse: Too large reply header (" << hdr_len << " > " << Config.maxReplyHeaderSize);
        *error = HTTP_HEADER_TOO_LARGE;
        return false;
    }

    if (hdr_len <= 0) {
        debugs(58, 3, "HttpMsg::parse: failed to find end of headers (eof: " << eof << ") in '" << buf->content() << "'");

        if (eof) // iff we have seen the end, this is an error
            *error = HTTP_INVALID_HEADER;

        return false;
    }

    const int res = httpMsgParseStep(buf->content(), buf->contentSize(), eof);

    if (res < 0) { // error
        debugs(58, 3, "HttpMsg::parse: cannot parse isolated headers in '" << buf->content() << "'");
        *error = HTTP_INVALID_HEADER;
        return false;
    }

    if (res == 0) {
        debugs(58, 2, "HttpMsg::parse: strange, need more data near '" << buf->content() << "'");
        *error = HTTP_INVALID_HEADER;
        return false; // but this should not happen due to headersEnd() above
    }

    assert(res > 0);
    debugs(58, 9, "HttpMsg::parse success (" << hdr_len << " bytes) near '" << buf->content() << "'");

    if (hdr_sz != (int)hdr_len) {
        debugs(58, 1, "internal HttpMsg::parse vs. headersEnd error: " <<
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
                blk_start = parse_start, blk_end = blk_start + strlen(blk_start);
            } else {
                PROF_stop(HttpMsg_httpMsgParseStep);
                return 0;
            }
        }

        if (!header.parse(blk_start, blk_end)) {
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
    header.delById(HDR_CONTENT_LENGTH); // if any
    header.putInt64(HDR_CONTENT_LENGTH, clen);
    content_length = clen;
}

/* returns true if connection should be "persistent"
 * after processing this message */
int
httpMsgIsPersistent(HttpVersion const &http_ver, const HttpHeader * hdr)
{
    if (http_ver > HttpVersion(1, 0)) {
        /*
         * for modern versions of HTTP: persistent unless there is
         * a "Connection: close" header.
         */
        return !httpHeaderHasConnDir(hdr, "close");
    } else {
        /*
         * Persistent connections in Netscape 3.x are allegedly broken,
         * return false if it is a browser connection.  If there is a
         * VIA header, then we assume this is NOT a browser connection.
         */
        const char *agent = hdr->getStr(HDR_USER_AGENT);

        if (agent && !hdr->has(HDR_VIA)) {
            if (!strncasecmp(agent, "Mozilla/3.", 10))
                return 0;

            if (!strncasecmp(agent, "Netscape/3.", 11))
                return 0;
        }

        /* for old versions of HTTP: persistent if has "keep-alive" */
        return httpHeaderHasConnDir(hdr, "keep-alive");
    }
}

void HttpMsg::packInto(Packer *p, bool full_uri) const
{
    packFirstLineInto(p, full_uri);
    header.packInto(p);
    packerAppend(p, "\r\n", 2);
}

void HttpMsg::hdrCacheInit()
{
    content_length = header.getInt64(HDR_CONTENT_LENGTH);
    assert(NULL == cache_control);
    cache_control = header.getCc();
}

/*
 * useful for debugging
 */
void HttpMsg::firstLineBuf(MemBuf& mb)
{
    Packer p;
    packerToMemInit(&p, &mb);
    packFirstLineInto(&p, true);
    packerClean(&p);
}

// use HTTPMSGLOCK() instead of calling this directly
HttpMsg *
HttpMsg::_lock()
{
    lock_count++;
    return this;
}

// use HTTPMSGUNLOCK() instead of calling this directly
void
HttpMsg::_unlock()
{
    assert(lock_count > 0);
    --lock_count;

    if (0 == lock_count)
        delete this;
}


void
HttpParserInit(HttpParser *hdr, const char *buf, int bufsiz)
{
    hdr->state = 1;
    hdr->buf = buf;
    hdr->bufsiz = bufsiz;
    hdr->req_start = hdr->req_end = -1;
    hdr->hdr_start = hdr->hdr_end = -1;
    debugs(74, 5, "httpParseInit: Request buffer is " << buf);
    hdr->m_start = hdr->m_end = -1;
    hdr->u_start = hdr->u_end = -1;
    hdr->v_start = hdr->v_end = -1;
    hdr->v_maj = hdr->v_min = 0;
}

#if MSGDODEBUG
/* XXX This should eventually turn into something inlined or #define'd */
int
HttpParserReqSz(HttpParser *hp)
{
    assert(hp->state == 1);
    assert(hp->req_start != -1);
    assert(hp->req_end != -1);
    return hp->req_end - hp->req_start + 1;
}


/*
 * This +1 makes it 'right' but won't make any sense if
 * there's a 0 byte header? This won't happen normally - a valid header
 * is at -least- a blank line (\n, or \r\n.)
 */
int
HttpParserHdrSz(HttpParser *hp)
{
    assert(hp->state == 1);
    assert(hp->hdr_start != -1);
    assert(hp->hdr_end != -1);
    return hp->hdr_end - hp->hdr_start + 1;
}

const char *
HttpParserHdrBuf(HttpParser *hp)
{
    assert(hp->state == 1);
    assert(hp->hdr_start != -1);
    assert(hp->hdr_end != -1);
    return hp->buf + hp->hdr_start;
}

int
HttpParserRequestLen(HttpParser *hp)
{
    return hp->hdr_end - hp->req_start + 1;
}
#endif

int
HttpParser::parseRequestFirstLine()
{
    int second_word = -1; // track the suspected URI start
    int first_whitespace = -1, last_whitespace = -1; // track the first and last SP byte
    int line_end = -1; // tracks the last byte BEFORE terminal \r\n or \n sequence

    debugs(74, 5, HERE << "parsing possible request: " << buf);

    // Single-pass parse: (provided we have the whole line anyways)

    req_start = 0;
    if (Config.onoff.relaxed_header_parser) {
        if (Config.onoff.relaxed_header_parser < 0 && buf[req_start] == ' ')
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "Whitespace bytes received ahead of method. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix spaces (other bytes are valid method values)
        for (; req_start < bufsiz && buf[req_start] == ' '; req_start++);
    }
    req_end = -1;
    for (int i = 0; i < bufsiz; i++) {
        // track first and last whitespace (SP only)
        if (buf[i] == ' ') {
            last_whitespace = i;
            if (first_whitespace < req_start)
                first_whitespace = i;
        }

        // track next non-SP/non-HT byte after first_whitespace
        if (second_word < first_whitespace && buf[i] != ' ' && buf[i] != '\t') {
            second_word = i;
        }

        // locate line terminator
        if (buf[i] == '\n') {
            req_end = i;
            line_end = i - 1;
            break;
        }
        if (i < bufsiz - 1 && buf[i] == '\r') {
            if (Config.onoff.relaxed_header_parser) {
                if (Config.onoff.relaxed_header_parser < 0 && buf[i + 1] == '\r')
                    debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                           "Series of carriage-return bytes received prior to line terminator. " <<
                           "Ignored due to relaxed_header_parser.");

                // Be tolerant of invalid multiple \r prior to terminal \n
                if (buf[i + 1] == '\n' || buf[i + 1] == '\r')
                    line_end = i - 1;
                while (i < bufsiz - 1 && buf[i + 1] == '\r')
                    i++;

                if (buf[i + 1] == '\n') {
                    req_end = i + 1;
                    break;
                }
            } else {
                if (buf[i + 1] == '\n') {
                    req_end = i + 1;
                    line_end = i - 1;
                    break;
                }
            }

            // RFC 2616 section 5.1
            // "No CR or LF is allowed except in the final CRLF sequence"
            return -1;
        }
    }
    if (req_end == -1) {
        debugs(74, 5, "Parser: retval 0: from " << req_start <<
               "->" << req_end << ": needs more data to complete first line.");
        return 0;
    }

    // NP: we have now seen EOL, more-data (0) cannot occur.
    //     From here on any failure is -1, success is 1


    // Input Validation:

    // Process what we now know about the line structure into field offsets
    // generating HTTP status for any aborts as we go.

    // First non-whitespace = beginning of method
    if (req_start > line_end) {
        return -1;
    }
    m_start = req_start;

    // First whitespace = end of method
    if (first_whitespace > line_end || first_whitespace < req_start) {
        return -1;
    }
    m_end = first_whitespace - 1;
    if (m_end < m_start) {
        return -1;
    }

    // First non-whitespace after first SP = beginning of URL+Version
    if (second_word > line_end || second_word < req_start) {
        return -1;
    }
    u_start = second_word;

    // RFC 1945: SP and version following URI are optional, marking version 0.9
    // we identify this by the last whitespace being earlier than URI start
    if (last_whitespace < second_word && last_whitespace >= req_start) {
        v_maj = 0;
        v_min = 9;
        u_end = line_end;
        return 1;
    } else {
        // otherwise last whitespace is somewhere after end of URI.
        u_end = last_whitespace;
        // crop any trailing whitespace in the area we think of as URI
        for (; u_end >= u_start && xisspace(buf[u_end]); u_end--);
    }
    if (u_end < u_start) {
        return -1;
    }

    // Last whitespace SP = before start of protocol/version
    if (last_whitespace >= line_end) {
        return -1;
    }
    v_start = last_whitespace + 1;
    v_end = line_end;

    // We only accept HTTP protocol requests right now.
    // TODO: accept other protocols; RFC 2326 (RTSP protocol) etc
    if ((v_end - v_start +1) < 5 || strncasecmp(&buf[v_start], "HTTP/", 5) != 0) {
#if USE_HTTP_VIOLATIONS
        // being lax; old parser accepted strange versions
        // there is a LOT of cases which are ambiguous, therefore we cannot use relaxed_header_parser here.
        v_maj = 0;
        v_min = 9;
        u_end = line_end;
        return 1;
#else
        return -1;
#endif
    }

    int i = v_start + sizeof("HTTP/") -1;

    /* next should be 1 or more digits */
    if (!isdigit(buf[i])) {
        return -1;
    }
    int maj = 0;
    for (; i <= line_end && (isdigit(buf[i])) && maj < 65536; i++) {
        maj = maj * 10;
        maj = maj + (buf[i]) - '0';
    }
    // catch too-big values or missing remainders
    if (maj >= 65536 || i > line_end) {
        return -1;
    }
    v_maj = maj;

    /* next should be .; we -have- to have this as we have a whole line.. */
    if (buf[i] != '.') {
        return -1;
    }
    // catch missing minor part
    if (++i > line_end) {
        return -1;
    }

    /* next should be one or more digits */
    if (!isdigit(buf[i])) {
        return -1;
    }
    int min = 0;
    for (; i <= line_end && (isdigit(buf[i])) && min < 65536; i++) {
        min = min * 10;
        min = min + (buf[i]) - '0';
    }
    // catch too-big values or trailing garbage
    if (min >= 65536 || i < line_end) {
        return -1;
    }
    v_min = min;

    /*
     * Rightio - we have all the schtuff. Return true; we've got enough.
     */
    return 1;
}

int
HttpParserParseReqLine(HttpParser *hmsg)
{
    PROF_start(HttpParserParseReqLine);
    int retcode = hmsg->parseRequestFirstLine();
    debugs(74, 5, "Parser: retval " << retcode << ": from " << hmsg->req_start <<
           "->" << hmsg->req_end << ": method " << hmsg->m_start << "->" <<
           hmsg->m_end << "; url " << hmsg->u_start << "->" << hmsg->u_end <<
           "; version " << hmsg->v_start << "->" << hmsg->v_end << " (" << hmsg->v_maj <<
           "/" << hmsg->v_min << ")");
    PROF_stop(HttpParserParseReqLine);
    return retcode;
}
