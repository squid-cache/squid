
/*
 * $Id: HttpReply.cc,v 1.97 2007/11/26 13:09:55 hno Exp $
 *
 * DEBUG: section 58    HTTP Reply (Response)
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
#include "SquidTime.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "ACLChecklist.h"
#include "MemBuf.h"

/* local constants */

/* If we receive a 304 from the origin during a cache revalidation, we must
 * update the headers of the existing entry. Specifically, we need to update all
 * end-to-end headers and not any hop-by-hop headers (rfc2616 13.5.3).
 *
 * This is not the whole story though: since it is possible for a faulty/malicious
 * origin server to set headers it should not in a 304, we must explicitly ignore
 * these too. Specifically all entity-headers except those permitted in a 304
 * (rfc2616 10.3.5) must be ignored.
 * 
 * The list of headers we don't update is made up of:
 *     all hop-by-hop headers
 *     all entity-headers except Expires and Content-Location
 */
static HttpHeaderMask Denied304HeadersMask;
static http_hdr_type Denied304HeadersArr[] =
    {
        // hop-by-hop headers
        HDR_CONNECTION, HDR_KEEP_ALIVE, HDR_PROXY_AUTHENTICATE, HDR_PROXY_AUTHORIZATION,
        HDR_TE, HDR_TRAILERS, HDR_TRANSFER_ENCODING, HDR_UPGRADE,
        // entity headers
        HDR_ALLOW, HDR_CONTENT_ENCODING, HDR_CONTENT_LANGUAGE, HDR_CONTENT_LENGTH,
        HDR_CONTENT_MD5, HDR_CONTENT_RANGE, HDR_CONTENT_TYPE, HDR_LAST_MODIFIED
    };

/* module initialization */
void
httpReplyInitModule(void)
{
    assert(HTTP_STATUS_NONE == 0); // HttpReply::parse() interface assumes that
    httpHeaderMaskInit(&Denied304HeadersMask, 0);
    httpHeaderCalcMask(&Denied304HeadersMask, Denied304HeadersArr, countof(Denied304HeadersArr));
}

HttpReply::HttpReply() : HttpMsg(hoReply), date (0), last_modified (0), expires (0), surrogate_control (NULL), content_range (NULL), keep_alive (0), protoPrefix("HTTP/")
{
    init();
}

HttpReply::~HttpReply()
{
    if (do_clean)
        clean();
}

void
HttpReply::init()
{
    httpBodyInit(&body);
    hdrCacheInit();
    httpStatusLineInit(&sline);
    pstate = psReadyToParseStartLine;
    do_clean = true;
}

void HttpReply::reset()
{

    // reset should not reset the protocol; could have made protoPrefix a
    // virtual function instead, but it is not clear whether virtual methods
    // are allowed with MEMPROXY_CLASS() and whether some cbdata void*
    // conversions are not going to kill virtual tables
    const String pfx = protoPrefix;
    clean();
    init();
    protoPrefix = pfx;
}

void
HttpReply::clean()
{
    // we used to assert that the pipe is NULL, but now the message only 
    // points to a pipe that is owned and initiated by another object.
    body_pipe = NULL;

    httpBodyClean(&body);
    hdrCacheClean();
    header.clean();
    httpStatusLineClean(&sline);
}

void
HttpReply::packHeadersInto(Packer * p) const
{
    httpStatusLinePackInto(&sline, p);
    header.packInto(p);
    packerAppend(p, "\r\n", 2);
}

void
HttpReply::packInto(Packer * p)
{
    packHeadersInto(p);
    httpBodyPackInto(&body, p);
}

/* create memBuf, create mem-based packer, pack, destroy packer, return MemBuf */
MemBuf *
HttpReply::pack()
{
    MemBuf *mb = new MemBuf;
    Packer p;

    mb->init();
    packerToMemInit(&p, mb);
    packInto(&p);
    packerClean(&p);
    return mb;
}

MemBuf *
httpPackedReply(HttpVersion ver, http_status status, const char *ctype,
                int64_t clen, time_t lmt, time_t expires)
{
    HttpReply *rep = new HttpReply;
    rep->setHeaders(ver, status, ctype, NULL, clen, lmt, expires);
    MemBuf *mb = rep->pack();
    delete rep;
    return mb;
}

HttpReply *
HttpReply::make304 () const
{
    static const http_hdr_type ImsEntries[] = {HDR_DATE, HDR_CONTENT_TYPE, HDR_EXPIRES, HDR_LAST_MODIFIED, /* eof */ HDR_OTHER};

    HttpReply *rv = new HttpReply;
    int t;
    HttpHeaderEntry *e;

    /* rv->content_length; */
    rv->date = date;
    rv->last_modified = last_modified;
    rv->expires = expires;
    rv->content_type = content_type;
    /* rv->cache_control */
    /* rv->content_range */
    /* rv->keep_alive */
    HttpVersion ver(1,0);
    httpStatusLineSet(&rv->sline, ver,
                      HTTP_NOT_MODIFIED, "");

    for (t = 0; ImsEntries[t] != HDR_OTHER; ++t)
        if ((e = header.findEntry(ImsEntries[t])))
            rv->header.addEntry(e->clone());

    /* rv->body */
    return rv;
}

MemBuf *
HttpReply::packed304Reply()
{
    /* Not as efficient as skipping the header duplication,
     * but easier to maintain
     */
    HttpReply *temp = make304 ();
    MemBuf *rv = temp->pack();
    delete temp;
    return rv;
}

void
HttpReply::setHeaders(HttpVersion ver, http_status status, const char *reason,
                      const char *ctype, int64_t clen, time_t lmt, time_t expires)
{
    HttpHeader *hdr;
    httpStatusLineSet(&sline, ver, status, reason);
    hdr = &header;
    hdr->putStr(HDR_SERVER, visible_appname_string);
    hdr->putStr(HDR_MIME_VERSION, "1.0");
    hdr->putTime(HDR_DATE, squid_curtime);

    if (ctype) {
        hdr->putStr(HDR_CONTENT_TYPE, ctype);
        content_type = ctype;
    } else
        content_type = String();

    if (clen >= 0)
        hdr->putInt64(HDR_CONTENT_LENGTH, clen);

    if (expires >= 0)
        hdr->putTime(HDR_EXPIRES, expires);

    if (lmt > 0)		/* this used to be lmt != 0 @?@ */
        hdr->putTime(HDR_LAST_MODIFIED, lmt);

    date = squid_curtime;

    content_length = clen;

    expires = expires;

    last_modified = lmt;
}

void
HttpReply::redirect(http_status status, const char *loc)
{
    HttpHeader *hdr;
    HttpVersion ver(1,0);
    httpStatusLineSet(&sline, ver, status, httpStatusString(status));
    hdr = &header;
    hdr->putStr(HDR_SERVER, full_appname_string);
    hdr->putTime(HDR_DATE, squid_curtime);
    hdr->putInt64(HDR_CONTENT_LENGTH, 0);
    hdr->putStr(HDR_LOCATION, loc);
    date = squid_curtime;
    content_length = 0;
}

/* compare the validators of two replies.
 * 1 = they match
 * 0 = they do not match
 */
int
HttpReply::validatorsMatch(HttpReply const * otherRep) const
{
    String one,two;
    assert (otherRep);
    /* Numbers first - easiest to check */
    /* Content-Length */
    /* TODO: remove -1 bypass */

    if (content_length != otherRep->content_length
            && content_length > -1 &&
            otherRep->content_length > -1)
        return 0;

    /* ETag */
    one = header.getStrOrList(HDR_ETAG);

    two = otherRep->header.getStrOrList(HDR_ETAG);

    if (!one.buf() || !two.buf() || strcasecmp (one.buf(), two.buf())) {
        one.clean();
        two.clean();
        return 0;
    }

    if (last_modified != otherRep->last_modified)
        return 0;

    /* MD5 */
    one = header.getStrOrList(HDR_CONTENT_MD5);

    two = otherRep->header.getStrOrList(HDR_CONTENT_MD5);

    if (!one.buf() || !two.buf() || strcasecmp (one.buf(), two.buf())) {
        one.clean();
        two.clean();
        return 0;
    }

    return 1;
}

void
HttpReply::updateOnNotModified(HttpReply const * freshRep)
{
    assert(freshRep);

    /* clean cache */
    hdrCacheClean();
    /* update raw headers */
    header.update(&freshRep->header,
                  (const HttpHeaderMask *) &Denied304HeadersMask);

    header.compact();
    /* init cache */
    hdrCacheInit();
}

/* internal routines */

time_t
HttpReply::hdrExpirationTime()
{
    /* The s-maxage and max-age directive takes priority over Expires */

    if (cache_control) {
        if (date >= 0) {
            if (cache_control->s_maxage >= 0)
                return date + cache_control->s_maxage;

            if (cache_control->max_age >= 0)
                return date + cache_control->max_age;
        } else {
            /*
             * Conservatively handle the case when we have a max-age
             * header, but no Date for reference?
             */

            if (cache_control->s_maxage >= 0)
                return squid_curtime;

            if (cache_control->max_age >= 0)
                return squid_curtime;
        }
    }

    if (Config.onoff.vary_ignore_expire &&
            header.has(HDR_VARY)) {
        const time_t d = header.getTime(HDR_DATE);
        const time_t e = header.getTime(HDR_EXPIRES);

        if (d == e)
            return -1;
    }

    if (header.has(HDR_EXPIRES)) {
        const time_t e = header.getTime(HDR_EXPIRES);
        /*
         * HTTP/1.0 says that robust implementations should consider
         * bad or malformed Expires header as equivalent to "expires
         * immediately."
         */
        return e < 0 ? squid_curtime : e;
    }

    return -1;
}

/* sync this routine when you update HttpReply struct */
void
HttpReply::hdrCacheInit()
{
    HttpMsg::hdrCacheInit();

    content_length = header.getInt64(HDR_CONTENT_LENGTH);
    date = header.getTime(HDR_DATE);
    last_modified = header.getTime(HDR_LAST_MODIFIED);
    surrogate_control = header.getSc();
    content_range = header.getContRange();
    keep_alive = httpMsgIsPersistent(sline.version, &header);
    const char *str = header.getStr(HDR_CONTENT_TYPE);

    if (str)
        content_type.limitInit(str, strcspn(str, ";\t "));
    else
        content_type = String();

    /* be sure to set expires after date and cache-control */
    expires = hdrExpirationTime();
}

/* sync this routine when you update HttpReply struct */
void
HttpReply::hdrCacheClean()
{
    content_type.clean();

    if (cache_control) {
        httpHdrCcDestroy(cache_control);
        cache_control = NULL;
    }

    if (surrogate_control) {
        httpHdrScDestroy(surrogate_control);
        surrogate_control = NULL;
    }

    if (content_range) {
        httpHdrContRangeDestroy(content_range);
        content_range = NULL;
    }
}

/*
 * Returns the body size of a HTTP response
 */
int64_t
HttpReply::bodySize(method_t method) const
{
    if (sline.version.major < 1)
        return -1;
    else if (METHOD_HEAD == method)
        return 0;
    else if (sline.status == HTTP_OK)
        (void) 0;		/* common case, continue */
    else if (sline.status == HTTP_NO_CONTENT)
        return 0;
    else if (sline.status == HTTP_NOT_MODIFIED)
        return 0;
    else if (sline.status < HTTP_OK)
        return 0;

    return content_length;
}

bool HttpReply::sanityCheckStartLine(MemBuf *buf, http_status *error)
{
    if (buf->contentSize() >= protoPrefix.size() && protoPrefix.cmp(buf->content(), protoPrefix.size()) != 0) {
        debugs(58, 3, "HttpReply::sanityCheckStartLine: missing protocol prefix (" << protoPrefix.buf() << ") in '" << buf->content() << "'");
        *error = HTTP_INVALID_HEADER;
        return false;
    }

    return true;
}

void HttpReply::packFirstLineInto(Packer *p, bool unused) const
{
    httpStatusLinePackInto(&sline, p);
}

bool HttpReply::parseFirstLine(const char *blk_start, const char *blk_end)
{
    return httpStatusLineParse(&sline, protoPrefix, blk_start, blk_end);
}

/* handy: resets and returns -1 */
int
HttpReply::httpMsgParseError()
{
    int result(HttpMsg::httpMsgParseError());
    /* indicate an error in the status line */
    sline.status = HTTP_INVALID_HEADER;
    return result;
}

/*
 * Indicate whether or not we would usually expect an entity-body
 * along with this response
 */
bool
HttpReply::expectingBody(method_t req_method, int64_t& theSize) const
{
    bool expectBody = true;

    if (req_method == METHOD_HEAD)
        expectBody = false;
    else if (sline.status == HTTP_NO_CONTENT)
        expectBody = false;
    else if (sline.status == HTTP_NOT_MODIFIED)
        expectBody = false;
    else if (sline.status < HTTP_OK)
        expectBody = false;
    else
        expectBody = true;

    if (expectBody) {
        if (header.hasListMember(HDR_TRANSFER_ENCODING, "chunked", ','))
            theSize = -1;
        else if (content_length >= 0)
            theSize = content_length;
        else
            theSize = -1;
    }

    return expectBody;
}

HttpReply *
HttpReply::clone() const
{
    HttpReply *rep = new HttpReply();
    rep->header.append(&header);
    rep->hdrCacheInit();
    rep->hdr_sz = hdr_sz;
    rep->http_ver = http_ver;
    rep->pstate = pstate;
    rep->protocol = protocol;
    rep->sline = sline;
    return rep;
}
