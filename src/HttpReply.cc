
/*
 * $Id: HttpReply.cc,v 1.79 2005/11/07 22:00:38 wessels Exp $
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
#include "Store.h"
#include "HttpReply.h"
#include "HttpHdrContRange.h"
#include "ACLChecklist.h"
#include "MemBuf.h"

/* local constants */

/* these entity-headers must be ignored if a bogus server sends them in 304 */
static HttpHeaderMask Denied304HeadersMask;
static http_hdr_type Denied304HeadersArr[] =
    {
        HDR_ALLOW, HDR_CONTENT_ENCODING, HDR_CONTENT_LANGUAGE, HDR_CONTENT_LENGTH,
        HDR_CONTENT_LOCATION, HDR_CONTENT_RANGE, HDR_LAST_MODIFIED, HDR_LINK,
        HDR_OTHER
    };


/* module initialization */
void
httpReplyInitModule(void)
{
    assert(HTTP_STATUS_NONE == 0); // HttpReply::parse() interface assumes that
    httpHeaderMaskInit(&Denied304HeadersMask, 0);
    httpHeaderCalcMask(&Denied304HeadersMask, (const int *) Denied304HeadersArr, countof(Denied304HeadersArr));
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
    httpBodyClean(&body);
    hdrCacheClean();
    httpHeaderClean(&header);
    httpStatusLineClean(&sline);
}

/* absorb: copy the contents of a new reply to the old one, destroy new one */
void
HttpReply::absorb(HttpReply * new_rep)
{
    assert(new_rep);
    clean();
    *this = *new_rep;
    new_rep->header.entries.clean();
    /* cannot use Clean() on new reply now! */
    new_rep->do_clean = false;
    new_rep->cache_control = NULL;	// helps with debugging
    delete new_rep;
}

void
HttpReply::packHeadersInto(Packer * p) const
{
    httpStatusLinePackInto(&sline, p);
    httpHeaderPackInto(&header, p);
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

/*
 * swap: create swap-based packer, pack, destroy packer
 * This eats the reply.
 */
void
HttpReply::swapOut(StoreEntry * e)
{
    assert(e);

    storeEntryReplaceObject(e, this);
}

MemBuf *
httpPackedReply(HttpVersion ver, http_status status, const char *ctype,
                int clen, time_t lmt, time_t expires)
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
        if ((e = httpHeaderFindEntry(&header, ImsEntries[t])))
            httpHeaderAddEntry(&rv->header, httpHeaderEntryClone(e));

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
                      const char *ctype, int clen, time_t lmt, time_t expires)
{
    HttpHeader *hdr;
    httpStatusLineSet(&sline, ver, status, reason);
    hdr = &header;
    httpHeaderPutStr(hdr, HDR_SERVER, visible_appname_string);
    httpHeaderPutStr(hdr, HDR_MIME_VERSION, "1.0");
    httpHeaderPutTime(hdr, HDR_DATE, squid_curtime);

    if (ctype) {
        httpHeaderPutStr(hdr, HDR_CONTENT_TYPE, ctype);
        content_type = ctype;
    } else
        content_type = String();

    if (clen >= 0)
        httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, clen);

    if (expires >= 0)
        httpHeaderPutTime(hdr, HDR_EXPIRES, expires);

    if (lmt > 0)		/* this used to be lmt != 0 @?@ */
        httpHeaderPutTime(hdr, HDR_LAST_MODIFIED, lmt);

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
    httpHeaderPutStr(hdr, HDR_SERVER, full_appname_string);
    httpHeaderPutTime(hdr, HDR_DATE, squid_curtime);
    httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, 0);
    httpHeaderPutStr(hdr, HDR_LOCATION, loc);
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
    one = httpHeaderGetStrOrList(&header, HDR_ETAG);

    two = httpHeaderGetStrOrList(&otherRep->header, HDR_ETAG);

    if (!one.buf() || !two.buf() || strcasecmp (one.buf(), two.buf())) {
        one.clean();
        two.clean();
        return 0;
    }

    if (last_modified != otherRep->last_modified)
        return 0;

    /* MD5 */
    one = httpHeaderGetStrOrList(&header, HDR_CONTENT_MD5);

    two = httpHeaderGetStrOrList(&otherRep->header, HDR_CONTENT_MD5);

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
    /* Can not update modified headers that don't match! */
    assert (validatorsMatch(freshRep));
    /* clean cache */
    hdrCacheClean();
    /* update raw headers */
    httpHeaderUpdate(&header, &freshRep->header,
                     (const HttpHeaderMask *) &Denied304HeadersMask);
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
            httpHeaderHas(&header, HDR_VARY)) {
        const time_t d = httpHeaderGetTime(&header, HDR_DATE);
        const time_t e = httpHeaderGetTime(&header, HDR_EXPIRES);

        if (d == e)
            return -1;
    }

    if (httpHeaderHas(&header, HDR_EXPIRES)) {
        const time_t e = httpHeaderGetTime(&header, HDR_EXPIRES);
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

    content_length = httpHeaderGetInt(&header, HDR_CONTENT_LENGTH);
    date = httpHeaderGetTime(&header, HDR_DATE);
    last_modified = httpHeaderGetTime(&header, HDR_LAST_MODIFIED);
    surrogate_control = httpHeaderGetSc(&header);
    content_range = httpHeaderGetContRange(&header);
    keep_alive = httpMsgIsPersistent(sline.version, &header);
    const char *str = httpHeaderGetStr(&header, HDR_CONTENT_TYPE);

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
int
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
