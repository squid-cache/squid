
/*
 * $Id: HttpReply.cc,v 1.77 2005/09/17 05:50:07 wessels Exp $
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


/* local routines */
static void httpReplyClean(HttpReply * rep);
static void httpReplyDoDestroy(HttpReply * rep);
static void httpReplyHdrCacheClean(HttpReply * rep);
static time_t httpReplyHdrExpirationTime(const HttpReply * rep);


/* module initialization */
void
httpReplyInitModule(void)
{
    assert(HTTP_STATUS_NONE == 0); // HttpReply::parse() interface assumes that
    httpHeaderMaskInit(&Denied304HeadersMask, 0);
    httpHeaderCalcMask(&Denied304HeadersMask, (const int *) Denied304HeadersArr, countof(Denied304HeadersArr));
}


HttpReply *
httpReplyCreate(void)
{
    HttpReply *rep = new HttpReply;
    debug(58, 7) ("creating rep: %p\n", rep);
    return rep;
}

HttpReply::HttpReply() : HttpMsg(hoReply), date (0), last_modified (0), expires (0), surrogate_control (NULL), content_range (NULL), keep_alive (0), protoPrefix("HTTP/")
{
    httpBodyInit(&body);
    hdrCacheInit();
    httpStatusLineInit(&sline);
}

void HttpReply::reset()
{
    httpReplyReset(this);
}

static void
httpReplyClean(HttpReply * rep)
{
    assert(rep);
    httpBodyClean(&rep->body);
    httpReplyHdrCacheClean(rep);
    httpHeaderClean(&rep->header);
    httpStatusLineClean(&rep->sline);
}

void
httpReplyDestroy(HttpReply * rep)
{
    assert(rep);
    debug(58, 7) ("destroying rep: %p\n", rep);
    httpReplyClean(rep);
    httpReplyDoDestroy(rep);
}

void
httpReplyReset(HttpReply * rep)
{
    // reset should not reset the protocol; could have made protoPrefix a
    // virtual function instead, but it is not clear whether virtual methods
    // are allowed with MEMPROXY_CLASS() and whether some cbdata void*
    // conversions are not going to kill virtual tables
    const String pfx = rep->protoPrefix;
    httpReplyClean(rep);
    *rep = HttpReply();
    rep->protoPrefix = pfx;
}

/* absorb: copy the contents of a new reply to the old one, destroy new one */
void
httpReplyAbsorb(HttpReply * rep, HttpReply * new_rep)
{
    assert(rep && new_rep);
    httpReplyClean(rep);
    *rep = *new_rep;
    new_rep->header.entries.clean();
    /* cannot use Clean() on new reply now! */
    new_rep->cache_control = NULL;	// helps with debugging
    httpReplyDoDestroy(new_rep);
}

/*
 * httpReplyParse takes character buffer of HTTP headers (buf),
 * which may not be NULL-terminated, and fills in an HttpReply
 * structure (rep).  The parameter 'end' specifies the offset to
 * the end of the reply headers.  The caller may know where the
 * end is, but is unable to NULL-terminate the buffer.  This function
 * returns true on success.
 */
bool
httpReplyParse(HttpReply * rep, const char *buf, ssize_t end)
{
    /*
     * this extra buffer/copy will be eliminated when headers become
     * meta-data in store. Currently we have to xstrncpy the buffer
     * becuase somebody may feed a non NULL-terminated buffer to
     * us.
     */
    MemBuf mb;
    int success;
    /* reset current state, because we are not used in incremental fashion */
    httpReplyReset(rep);
    /* put a string terminator.  s is how many bytes to touch in
     * 'buf' including the terminating NULL. */
    mb.init();
    mb.append(buf, end);
    mb.append("\0", 1);
    success = rep->httpMsgParseStep(mb.buf, 0);
    mb.clean();
    return success == 1;
}

void
httpReplyPackHeadersInto(const HttpReply * rep, Packer * p)
{
    assert(rep);
    httpStatusLinePackInto(&rep->sline, p);
    httpHeaderPackInto(&rep->header, p);
    packerAppend(p, "\r\n", 2);
}

void
httpReplyPackInto(const HttpReply * rep, Packer * p)
{
    httpReplyPackHeadersInto(rep, p);
    httpBodyPackInto(&rep->body, p);
}

/* create memBuf, create mem-based packer,  pack, destroy packer, return MemBuf */
MemBuf *
httpReplyPack(const HttpReply * rep)
{
    MemBuf *mb = new MemBuf;
    Packer p;
    assert(rep);

    mb->init();
    packerToMemInit(&p, mb);
    httpReplyPackInto(rep, &p);
    packerClean(&p);
    return mb;
}

/* swap: create swap-based packer, pack, destroy packer
 * This eats the reply.
 */
void
httpReplySwapOut(HttpReply * rep, StoreEntry * e)
{
    assert(rep && e);

    storeEntryReplaceObject(e, rep);
}

MemBuf *
httpPackedReply(HttpVersion ver, http_status status, const char *ctype,
                int clen, time_t lmt, time_t expires)
{
    HttpReply *rep = httpReplyCreate();
    httpReplySetHeaders(rep, ver, status, ctype, NULL, clen, lmt, expires);
    MemBuf *mb = httpReplyPack(rep);
    httpReplyDestroy(rep);
    return mb;
}

HttpReply *
httpReplyMake304 (const HttpReply * rep)
{
    static const http_hdr_type ImsEntries[] = {HDR_DATE, HDR_CONTENT_TYPE, HDR_EXPIRES, HDR_LAST_MODIFIED, /* eof */ HDR_OTHER};

    HttpReply *rv;
    int t;
    HttpHeaderEntry *e;
    assert(rep);

    rv = httpReplyCreate ();
    /* rv->content_length; */
    rv->date = rep->date;
    rv->last_modified = rep->last_modified;
    rv->expires = rep->expires;
    rv->content_type = rep->content_type;
    /* rv->cache_control */
    /* rv->content_range */
    /* rv->keep_alive */
    HttpVersion ver(1,0);
    httpStatusLineSet(&rv->sline, ver,
                      HTTP_NOT_MODIFIED, "");

    for (t = 0; ImsEntries[t] != HDR_OTHER; ++t)
        if ((e = httpHeaderFindEntry(&rep->header, ImsEntries[t])))
            httpHeaderAddEntry(&rv->header, httpHeaderEntryClone(e));

    /* rv->body */
    return rv;
}

MemBuf *
httpPacked304Reply(const HttpReply * rep)
{
    /* Not as efficient as skipping the header duplication,
     * but easier to maintain
     */
    HttpReply *temp;
    assert (rep);
    temp = httpReplyMake304 (rep);
    MemBuf *rv = httpReplyPack(temp);
    httpReplyDestroy (temp);
    return rv;
}

void
httpReplySetHeaders(HttpReply * reply, HttpVersion ver, http_status status, const char *reason,
                    const char *ctype, int clen, time_t lmt, time_t expires)
{
    HttpHeader *hdr;
    assert(reply);
    httpStatusLineSet(&reply->sline, ver, status, reason);
    hdr = &reply->header;
    httpHeaderPutStr(hdr, HDR_SERVER, visible_appname_string);
    httpHeaderPutStr(hdr, HDR_MIME_VERSION, "1.0");
    httpHeaderPutTime(hdr, HDR_DATE, squid_curtime);

    if (ctype) {
        httpHeaderPutStr(hdr, HDR_CONTENT_TYPE, ctype);
        reply->content_type = ctype;
    } else
        reply->content_type = String();

    if (clen >= 0)
        httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, clen);

    if (expires >= 0)
        httpHeaderPutTime(hdr, HDR_EXPIRES, expires);

    if (lmt > 0)		/* this used to be lmt != 0 @?@ */
        httpHeaderPutTime(hdr, HDR_LAST_MODIFIED, lmt);

    reply->date = squid_curtime;

    reply->content_length = clen;

    reply->expires = expires;

    reply->last_modified = lmt;
}

void
httpRedirectReply(HttpReply * reply, http_status status, const char *loc)
{
    HttpHeader *hdr;
    assert(reply);
    HttpVersion ver(1,0);
    httpStatusLineSet(&reply->sline, ver, status, httpStatusString(status));
    hdr = &reply->header;
    httpHeaderPutStr(hdr, HDR_SERVER, full_appname_string);
    httpHeaderPutTime(hdr, HDR_DATE, squid_curtime);
    httpHeaderPutInt(hdr, HDR_CONTENT_LENGTH, 0);
    httpHeaderPutStr(hdr, HDR_LOCATION, loc);
    reply->date = squid_curtime;
    reply->content_length = 0;
}

/* compare the validators of two replies.
 * 1 = they match
 * 0 = they do not match
 */
int
httpReplyValidatorsMatch(HttpReply const * rep, HttpReply const * otherRep)
{
    String one,two;
    assert (rep && otherRep);
    /* Numbers first - easiest to check */
    /* Content-Length */
    /* TODO: remove -1 bypass */

    if (rep->content_length != otherRep->content_length
            && rep->content_length > -1 &&
            otherRep->content_length > -1)
        return 0;

    /* ETag */
    one = httpHeaderGetStrOrList(&rep->header, HDR_ETAG);

    two = httpHeaderGetStrOrList(&otherRep->header, HDR_ETAG);

    if (!one.buf() || !two.buf() || strcasecmp (one.buf(), two.buf())) {
        one.clean();
        two.clean();
        return 0;
    }

    if (rep->last_modified != otherRep->last_modified)
        return 0;

    /* MD5 */
    one = httpHeaderGetStrOrList(&rep->header, HDR_CONTENT_MD5);

    two = httpHeaderGetStrOrList(&otherRep->header, HDR_CONTENT_MD5);

    if (!one.buf() || !two.buf() || strcasecmp (one.buf(), two.buf())) {
        one.clean();
        two.clean();
        return 0;
    }

    return 1;
}


void
HttpReply::httpReplyUpdateOnNotModified(HttpReply const * freshRep)
{
    assert(freshRep);
    /* Can not update modified headers that don't match! */
    assert (httpReplyValidatorsMatch(this, freshRep));
    /* clean cache */
    httpReplyHdrCacheClean(this);
    /* update raw headers */
    httpHeaderUpdate(&header, &freshRep->header,
                     (const HttpHeaderMask *) &Denied304HeadersMask);
    /* init cache */
    hdrCacheInit();
}


/* internal routines */

/* internal function used by Destroy and Absorb */
static void
httpReplyDoDestroy(HttpReply * rep)
{
    delete rep;
}

static time_t
httpReplyHdrExpirationTime(const HttpReply * rep)
{
    /* The s-maxage and max-age directive takes priority over Expires */

    if (rep->cache_control) {
        if (rep->date >= 0) {
            if (rep->cache_control->s_maxage >= 0)
                return rep->date + rep->cache_control->s_maxage;

            if (rep->cache_control->max_age >= 0)
                return rep->date + rep->cache_control->max_age;
        } else {
            /*
             * Conservatively handle the case when we have a max-age
             * header, but no Date for reference?
             */

            if (rep->cache_control->s_maxage >= 0)
                return squid_curtime;

            if (rep->cache_control->max_age >= 0)
                return squid_curtime;
        }
    }

    if (Config.onoff.vary_ignore_expire &&
            httpHeaderHas(&rep->header, HDR_VARY)) {
        const time_t d = httpHeaderGetTime(&rep->header, HDR_DATE);
        const time_t e = httpHeaderGetTime(&rep->header, HDR_EXPIRES);

        if (d == e)
            return -1;
    }

    if (httpHeaderHas(&rep->header, HDR_EXPIRES)) {
        const time_t e = httpHeaderGetTime(&rep->header, HDR_EXPIRES);
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
    expires = httpReplyHdrExpirationTime(this);
}

/* sync this routine when you update HttpReply struct */
static void
httpReplyHdrCacheClean(HttpReply * rep)
{
    rep->content_type.clean();

    if (rep->cache_control) {
        httpHdrCcDestroy(rep->cache_control);
        rep->cache_control = NULL;
    }

    if (rep->surrogate_control) {
        httpHdrScDestroy(rep->surrogate_control);
        rep->surrogate_control = NULL;
    }

    if (rep->content_range) {
        httpHdrContRangeDestroy(rep->content_range);
        rep->content_range = NULL;
    }
}

/*
 * Returns the body size of a HTTP response
 */
int
httpReplyBodySize(method_t method, HttpReply const * reply)
{
    if (reply->sline.version.major < 1)
        return -1;
    else if (METHOD_HEAD == method)
        return 0;
    else if (reply->sline.status == HTTP_OK)
        (void) 0;		/* common case, continue */
    else if (reply->sline.status == HTTP_NO_CONTENT)
        return 0;
    else if (reply->sline.status == HTTP_NOT_MODIFIED)
        return 0;
    else if (reply->sline.status < HTTP_OK)
        return 0;

    return reply->content_length;
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
