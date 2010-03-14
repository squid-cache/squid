
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
    if ((http_ver.major >= 1) && (http_ver.minor >= 1)) {
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

/**
 * Attempt to parse the request line.
 *
 * This will set the values in hmsg that it determines. One may end up
 * with a partially-parsed buffer; the return value tells you whether
 * the values are valid or not.
 *
 * \retval	1 if parsed correctly
 * \retval	0 if more is needed
 * \retval	-1 if error
 *
 * TODO:
 *   * have it indicate "error" and "not enough" as two separate conditions!
 *   * audit this code as off-by-one errors are probably everywhere!
 */
int
HttpParserParseReqLine(HttpParser *hmsg)
{
    int i = 0;
    int retcode = 0;
    unsigned int maj = 0, min = 0;
    int last_whitespace = -1, line_end = -1;

    debugs(74, 5, "httpParserParseReqLine: parsing " << hmsg->buf);

    PROF_start(HttpParserParseReqLine);
    /* Find \r\n - end of URL+Version (and the request) */
    hmsg->req_end = -1;
    for (i = 0; i < hmsg->bufsiz; i++) {
        if (hmsg->buf[i] == '\n') {
            hmsg->req_end = i;
            break;
        }
        if (i < hmsg->bufsiz - 1 && hmsg->buf[i] == '\r' && hmsg->buf[i + 1] == '\n') {
            hmsg->req_end = i + 1;
            break;
        }
    }
    if (hmsg->req_end == -1) {
        retcode = 0;
        goto finish;
    }
    assert(hmsg->buf[hmsg->req_end] == '\n');
    /* Start at the beginning again */
    i = 0;

    /* Find first non-whitespace - beginning of method */
    for (; i < hmsg->req_end && (xisspace(hmsg->buf[i])); i++);
    if (i >= hmsg->req_end) {
        retcode = 0;
        goto finish;
    }
    hmsg->m_start = i;
    hmsg->req_start = i;

    /* Find first whitespace - end of method */
    for (; i < hmsg->req_end && (! xisspace(hmsg->buf[i])); i++);
    if (i >= hmsg->req_end) {
        retcode = 0;
        goto finish;
    }
    hmsg->m_end = i - 1;

    /* Find first non-whitespace - beginning of URL+Version */
    for (; i < hmsg->req_end && (xisspace(hmsg->buf[i])); i++);
    if (i >= hmsg->req_end) {
        retcode = 0;
        goto finish;
    }
    hmsg->u_start = i;

    /* Find \r\n or \n - thats the end of the line. Keep track of the last whitespace! */
    for (; i <= hmsg->req_end; i++) {
        /* If \n - its end of line */
        if (hmsg->buf[i] == '\n') {
            line_end = i;
            break;
        }
        /* XXX could be off-by-one wrong! */
        if (hmsg->buf[i] == '\r' && (i + 1) <= hmsg->req_end && hmsg->buf[i+1] == '\n') {
            line_end = i;
            break;
        }
        /* If its a whitespace, note it as it'll delimit our version */
        if (hmsg->buf[i] == ' ' || hmsg->buf[i] == '\t') {
            last_whitespace = i;
        }
    }
    if (i > hmsg->req_end) {
        retcode = 0;
        goto finish;
    }

    /* At this point we don't need the 'i' value; so we'll recycle it for version parsing */

    /*
     * At this point: line_end points to the first eol char (\r or \n);
     * last_whitespace points to the last whitespace char in the URL.
     * We know we have a full buffer here!
     */
    if (last_whitespace == -1) {
        maj = 0;
        min = 9;
        hmsg->u_end = line_end - 1;
        assert(hmsg->u_end >= hmsg->u_start);
    } else {
        /* Find the first non-whitespace after last_whitespace */
        /* XXX why <= vs < ? I do need to really re-audit all of this ..*/
        for (i = last_whitespace; i <= hmsg->req_end && xisspace(hmsg->buf[i]); i++);
        if (i > hmsg->req_end) {
            retcode = 0;
            goto finish;
        }

        /* is it http/ ? if so, we try parsing. If not, the URL is the whole line; version is 0.9 */
        if (i + 5 >= hmsg->req_end || (strncasecmp(&hmsg->buf[i], "HTTP/", 5) != 0)) {
            maj = 0;
            min = 9;
            hmsg->u_end = line_end - 1;
            assert(hmsg->u_end >= hmsg->u_start);
        } else {
            /* Ok, lets try parsing! Yes, this needs refactoring! */
            hmsg->v_start = i;
            i += 5;

            /* next should be 1 or more digits */
            maj = 0;
            for (; i < hmsg->req_end && (isdigit(hmsg->buf[i])) && maj < 65536; i++) {
                maj = maj * 10;
                maj = maj + (hmsg->buf[i]) - '0';
            }
            if (maj >= 65536) {
                retcode = -1;
                goto finish;
            }
            if (i >= hmsg->req_end) {
                retcode = 0;
                goto finish;
            }

            /* next should be .; we -have- to have this as we have a whole line.. */
            if (hmsg->buf[i] != '.') {
                retcode = 0;
                goto finish;
            }
            if (i + 1 >= hmsg->req_end) {
                retcode = 0;
                goto finish;
            }

            /* next should be one or more digits */
            i++;
            min = 0;
            for (; i < hmsg->req_end && (isdigit(hmsg->buf[i])) && min < 65536; i++) {
                min = min * 10;
                min = min + (hmsg->buf[i]) - '0';
            }

            if (min >= 65536) {
                retcode = -1;
                goto finish;
            }

            /* Find whitespace, end of version */
            hmsg->v_end = i;
            hmsg->u_end = last_whitespace - 1;
        }
    }

    /*
     * Rightio - we have all the schtuff. Return true; we've got enough.
     */
    retcode = 1;

finish:
    hmsg->v_maj = maj;
    hmsg->v_min = min;
    PROF_stop(HttpParserParseReqLine);
    debugs(74, 5, "Parser: retval " << retcode << ": from " << hmsg->req_start <<
           "->" << hmsg->req_end << ": method " << hmsg->m_start << "->" <<
           hmsg->m_end << "; url " << hmsg->u_start << "->" << hmsg->u_end <<
           "; version " << hmsg->v_start << "->" << hmsg->v_end << " (" << maj <<
           "/" << min << ")");

    return retcode;
}

