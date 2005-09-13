
/*
 * $Id: HttpMsg.cc,v 1.15 2005/09/12 23:28:57 wessels Exp $
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
#include "HttpRequest.h"
#include "HttpReply.h"

HttpMsg::HttpMsg(http_hdr_owner_type owner): header(owner),
        cache_control(NULL), hdr_sz(0), content_length(0), protocol(PROTO_NONE),
        pstate(psReadyToParseStartLine)
{}


HttpMsgParseState &operator++ (HttpMsgParseState &aState)
{
    int tmp = (int)aState;
    aState = (HttpMsgParseState)(++tmp);
    return aState;
}


/* find end of headers */
int
httpMsgIsolateHeaders(const char **parse_start, const char **blk_start, const char **blk_end)
{
    /*
     * parse_start points to the first line of HTTP message *headers*,
     * not including the request or status lines
     */
    size_t l = strlen(*parse_start);
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
    // TODO: Remove? httpReplyParseStep() should do similar checks
    const size_t hdr_len = headersEnd(buf->content(), buf->contentSize());

    if (hdr_len <= 0) {
        debugs(58, 3, "HttpMsg::parse: failed to find end of headers " <<
               "(eof: " << eof << ") in '" << buf->content() << "'");

        if (eof) // iff we have seen the end, this is an error
            *error = HTTP_INVALID_HEADER;

        return false;
    }

    // TODO: move to httpReplyParseStep()
    if (hdr_len > Config.maxReplyHeaderSize) {
        debugs(58, 1, "HttpMsg::parse: Too large reply header (" <<
               hdr_len << " > " << Config.maxReplyHeaderSize);
        *error = HTTP_HEADER_TOO_LARGE;
        return false;
    }

    if (!sanityCheckStartLine(buf, error))	// redundant; could be remvoed
        return false;

    const int res = httpMsgParseStep(buf->content(), eof);

    if (res < 0) { // error
        debugs(58, 3, "HttpMsg::parse: cannot parse isolated headers " <<
               "in '" << buf->content() << "'");
        *error = HTTP_INVALID_HEADER;
        return false;
    }

    if (res == 0) {
        debugs(58, 2, "HttpMsg::parse: strange, need more data near '" <<
               buf->content() << "'");
        return false; // but this should not happen due to headersEnd() above
    }

    assert(res > 0);
    debugs(58, 9, "HttpMsg::parse success (" << hdr_len << " bytes) " <<
           "near '" << buf->content() << "'");

    if (hdr_sz != (int)hdr_len) {
        debugs(58, 1, "internal HttpMsg::parse vs. headersEnd error: " <<
               hdr_sz << " != " << hdr_len);
        hdr_sz = (int)hdr_len; // because old http.cc code used hdr_len
    }

    return true;
}



/*
 * parses a 0-terminating buffer into HttpMsg.
 * Returns:
 *      1 -- success
 *       0 -- need more data (partial parse)
 *      -1 -- parse error
 */
int
HttpMsg::httpMsgParseStep(const char *buf, int atEnd)
{
    const char *parse_start = buf;
    const char *blk_start, *blk_end;
    const char **parse_end_ptr = &blk_end;
    assert(parse_start);
    assert(pstate < psParsed);
    HttpReply *rep = dynamic_cast<HttpReply*>(this);
    HttpRequest *req = dynamic_cast<HttpRequest*>(this);

    *parse_end_ptr = parse_start;

    if (pstate == psReadyToParseStartLine) {
        if (!httpMsgIsolateStart(&parse_start, &blk_start, &blk_end))
            return 0;

        if (rep) {
            if (!httpStatusLineParse(&rep->sline, rep->protoPrefix, blk_start, blk_end))
                return httpMsgParseError();
        } else if (req) {
            if (!req->parseRequestLine(blk_start, blk_end))
                return httpMsgParseError();
        }

        *parse_end_ptr = parse_start;

        hdr_sz = *parse_end_ptr - buf;

        ++pstate;
    }

    if (pstate == psReadyToParseHeaders) {
        if (!httpMsgIsolateHeaders(&parse_start, &blk_start, &blk_end)) {
            if (atEnd)
                blk_start = parse_start, blk_end = blk_start + strlen(blk_start);
            else
                return 0;
        }

        if (!httpHeaderParse(&header, blk_start, blk_end))
            return httpMsgParseError();

        if (rep)
            httpReplyHdrCacheInit(rep);
        else if (req)
            httpRequestHdrCacheInit(req);

        *parse_end_ptr = parse_start;

        hdr_sz = *parse_end_ptr - buf;

        ++pstate;
    }

    return 1;
}


/* handy: resets and returns -1 */
int
HttpMsg::httpMsgParseError()
{
    reset();
    /* indicate an error */

    if (HttpReply *rep = dynamic_cast<HttpReply*>(this))
        rep->sline.status = HTTP_INVALID_HEADER;

    return -1;
}



/* returns true if connection should be "persistent"
 * after processing this message */
int
httpMsgIsPersistent(HttpVersion const &http_ver, const HttpHeader * hdr)
{
#if WHEN_SQUID_IS_NOT_HTTP1_1

    if ((http_ver.major >= 1) && (http_ver.minor >= 1)) {
        /*
         * for modern versions of HTTP: persistent unless there is
         * a "Connection: close" header.
         */
        return !httpHeaderHasConnDir(hdr, "close");
    } else
#else
    {
#endif
        /*
         * Persistent connections in Netscape 3.x are allegedly broken,
         * return false if it is a browser connection.  If there is a
         * VIA header, then we assume this is NOT a browser connection.
         */
        const char *agent = httpHeaderGetStr(hdr, HDR_USER_AGENT);

    if (agent && !httpHeaderHas(hdr, HDR_VIA)) {
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
    httpHeaderPackInto(&header, p);
    packerAppend(p, "\r\n", 2);
}


