
/*
 * $Id: HttpReply.cc,v 1.20 1998/05/22 05:19:09 rousskov Exp $
 *
 * DEBUG: section 58    HTTP Reply (Response)
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"


/* local constants */

/* local routines */
static void httpReplyDoDestroy(HttpReply * rep);
static void httpReplyHdrCacheInit(HttpReply * rep);
static void httpReplyHdrCacheClean(HttpReply * rep);
static int httpReplyParseStep(HttpReply * rep, const char *parse_start, int atEnd);
static int httpReplyParseError(HttpReply * rep);
static int httpReplyIsolateStart(const char **parse_start, const char **blk_start, const char **blk_end);


HttpReply *
httpReplyCreate()
{
    HttpReply *rep = memAllocate(MEM_HTTP_REPLY);
    debug(58, 7) ("creating rep: %p\n", rep);
    httpReplyInit(rep);
    return rep;
}

void
httpReplyInit(HttpReply * rep)
{
    assert(rep);
    rep->hdr_sz = 0;
    rep->pstate = psReadyToParseStartLine;
    httpBodyInit(&rep->body);
    httpHeaderInit(&rep->header);
    httpReplyHdrCacheInit(rep);
    httpStatusLineInit(&rep->sline);
}

void
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
    httpReplyClean(rep);
    httpReplyInit(rep);
}

/* absorb: copy the contents of a new reply to the old one, destroy new one */
void
httpReplyAbsorb(HttpReply * rep, HttpReply * new_rep)
{
    assert(rep && new_rep);
    httpReplyClean(rep);
    *rep = *new_rep;
    /* cannot use Clean() on new reply now! */
    httpReplyDoDestroy(new_rep);
}

/* parses a buffer that may not be 0-terminated */
int
httpReplyParse(HttpReply * rep, const char *buf)
{
    /*
     * this extra buffer/copy will be eliminated when headers become meta-data
     * in store. Currently we have to xstrncpy the buffer becuase store.c may
     * feed a non 0-terminated buffer to us @?@.
     */
    char *headers = memAllocate(MEM_4K_BUF);
    int success;
    /* reset current state, because we are not used in incremental fashion */
    httpReplyReset(rep);
    /* put a 0-terminator */
    xstrncpy(headers, buf, 4096);
    success = httpReplyParseStep(rep, headers, 0);
    memFree(MEM_4K_BUF, headers);
    return success == 1;
}

void
httpReplyPackInto(const HttpReply * rep, Packer * p)
{
    assert(rep);
    httpStatusLinePackInto(&rep->sline, p);
    httpHeaderPackInto(&rep->header, p);
    packerAppend(p, "\r\n", 2);
    httpBodyPackInto(&rep->body, p);
}

/* create memBuf, create mem-based packer,  pack, destroy packer, return MemBuf */
MemBuf
httpReplyPack(const HttpReply * rep)
{
    MemBuf mb;
    Packer p;
    assert(rep);

    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    httpReplyPackInto(rep, &p);
    packerClean(&p);
    return mb;
}

/* swap: create swap-based packer, pack, destroy packer */
void
httpReplySwapOut(const HttpReply * rep, StoreEntry * e)
{
    Packer p;
    assert(rep && e);

    packerToStoreInit(&p, e);
    httpReplyPackInto(rep, &p);
    packerClean(&p);
}

MemBuf
httpPackedReply(double ver, http_status status, const char *ctype,
    int clen, time_t lmt, time_t expires)
{
    HttpReply *rep = httpReplyCreate();
    MemBuf mb;
    httpReplySetHeaders(rep, ver, status, ctype, NULL, clen, lmt, expires);
    mb = httpReplyPack(rep);
    httpReplyDestroy(rep);
    return mb;
}

MemBuf
httpPacked304Reply(const HttpReply * rep)
{
    static const http_hdr_type ImsEntries[] =
    {HDR_DATE, HDR_CONTENT_LENGTH, HDR_CONTENT_TYPE, HDR_EXPIRES, HDR_LAST_MODIFIED, /* eof */ HDR_OTHER};
    http_hdr_type t;
    MemBuf mb;
    Packer p;
    HttpHeaderEntry *e;
    assert(rep);

    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    memBufPrintf(&mb, "%s", "HTTP/1.0 304 Not Modified\r\n");
    for (t = 0; ImsEntries[t] != HDR_OTHER; ++t)
	if ((e = httpHeaderFindEntry(&rep->header, ImsEntries[t])))
	    httpHeaderEntryPackInto(e, &p);
    memBufAppend(&mb, "\r\n", 2);
    packerClean(&p);
    return mb;
}

void
httpReplySetHeaders(HttpReply * reply, double ver, http_status status, const char *reason,
    const char *ctype, int clen, time_t lmt, time_t expires)
{
    HttpHeader *hdr;
    assert(reply);
    httpStatusLineSet(&reply->sline, ver, status, reason);
    hdr = &reply->header;
    httpHeaderPutStr(hdr, HDR_SERVER, full_appname_string);
    httpHeaderPutStr(hdr, HDR_MIME_VERSION, "1.0");
    httpHeaderPutTime(hdr, HDR_DATE, squid_curtime);
    if (ctype) {
	httpHeaderPutStr(hdr, HDR_CONTENT_TYPE, ctype);
	stringInit(&reply->content_type, ctype);
    } else
	reply->content_type = StringNull;
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
httpReplyUpdateOnNotModified(HttpReply * rep, HttpReply * freshRep)
{
#if OLD_CODE
    rep->cache_control = freshRep->cache_control;
    rep->misc_headers = freshRep->misc_headers;
    if (freshRep->date > -1)
	rep->date = freshRep->date;
    if (freshRep->last_modified > -1)
	rep->last_modified = freshRep->last_modified;
    if (freshRep->expires > -1)
	rep->expires = freshRep->expires;
#endif
    assert(rep && freshRep);
    /* clean cache */
    httpReplyHdrCacheClean(rep);
    /* update raw headers */
    httpHeaderUpdate(&rep->header, &freshRep->header);
    /* init cache */
    httpReplyHdrCacheInit(rep);
}


/* internal routines */

/* internal function used by Destroy and Absorb */
static void
httpReplyDoDestroy(HttpReply * rep)
{
    memFree(MEM_HTTP_REPLY, rep);
}

/* sync this routine when you update HttpReply struct */
static void
httpReplyHdrCacheInit(HttpReply * rep)
{
    const HttpHeader *hdr = &rep->header;
    const char *str;
    rep->content_length = httpHeaderGetInt(hdr, HDR_CONTENT_LENGTH);
    rep->date = httpHeaderGetTime(hdr, HDR_DATE);
    rep->last_modified = httpHeaderGetTime(hdr, HDR_LAST_MODIFIED);
    rep->expires = httpHeaderGetTime(hdr, HDR_EXPIRES);
    str = httpHeaderGetStr(hdr, HDR_CONTENT_TYPE);
    if (str)
	stringLimitInit(&rep->content_type, str, strcspn(str, ";\t "));
    else
	rep->content_type = StringNull;
    rep->cache_control = httpHeaderGetCc(hdr);
    rep->content_range = httpHeaderGetContRange(hdr);
    rep->keep_alive = httpMsgIsPersistent(rep->sline.version, &rep->header);
    /* final adjustments */
    /* The max-age directive takes priority over Expires, check it first */
    if (rep->cache_control && rep->cache_control->max_age >= 0)
	rep->expires = squid_curtime + rep->cache_control->max_age;
    else
	/*
	 * The HTTP/1.0 specs says that robust implementations should consider bad
	 * or malformed Expires header as equivalent to "expires immediately."
	 */
    if (rep->expires < 0 && httpHeaderHas(hdr, HDR_EXPIRES))
	rep->expires = squid_curtime;
}

/* sync this routine when you update HttpReply struct */
static void
httpReplyHdrCacheClean(HttpReply * rep)
{
    stringClean(&rep->content_type);
    if (rep->cache_control)
	httpHdrCcDestroy(rep->cache_control);
    if (rep->content_range)
	httpHdrContRangeDestroy(rep->content_range);
}

/*
 * parses a 0-terminating buffer into HttpReply. 
 * Returns:
 *      +1 -- success 
 *       0 -- need more data (partial parse)
 *      -1 -- parse error
 */
static int
httpReplyParseStep(HttpReply * rep, const char *buf, int atEnd)
{
    const char *parse_start = buf;
    const char *blk_start, *blk_end;
    const char **parse_end_ptr = &blk_end;
    assert(rep);
    assert(parse_start);
    assert(rep->pstate < psParsed);

    *parse_end_ptr = parse_start;
    if (rep->pstate == psReadyToParseStartLine) {
	if (!httpReplyIsolateStart(&parse_start, &blk_start, &blk_end))
	    return 0;
	if (!httpStatusLineParse(&rep->sline, blk_start, blk_end))
	    return httpReplyParseError(rep);

	*parse_end_ptr = parse_start;
	rep->hdr_sz = *parse_end_ptr - buf;
	rep->pstate++;
    }
    if (rep->pstate == psReadyToParseHeaders) {
	if (!httpMsgIsolateHeaders(&parse_start, &blk_start, &blk_end)) {
	    if (atEnd)
		blk_start = parse_start, blk_end = blk_start + strlen(blk_start);
	    else
		return 0;
        }
	if (!httpHeaderParse(&rep->header, blk_start, blk_end))
	    return httpReplyParseError(rep);

	httpReplyHdrCacheInit(rep);

	*parse_end_ptr = parse_start;
	rep->hdr_sz = *parse_end_ptr - buf;
	rep->pstate++;
    }
    return 1;
}

/* handy: resets and returns -1 */
static int
httpReplyParseError(HttpReply * rep)
{
    assert(rep);
    /* reset */
    httpReplyReset(rep);
    /* indicate an error */
    rep->sline.status = HTTP_INVALID_HEADER;
    return -1;
}

/* find first CRLF */
static int
httpReplyIsolateStart(const char **parse_start, const char **blk_start, const char **blk_end)
{
    int slen = strcspn(*parse_start, "\r\n");
    if (!(*parse_start)[slen])	/* no CRLF found */
	return 0;

    *blk_start = *parse_start;
    *blk_end = *blk_start + slen;
    if (**blk_end == '\r')	/* CR */
	(*blk_end)++;
    if (**blk_end == '\n')	/* LF */
	(*blk_end)++;

    *parse_start = *blk_end;
    return 1;
}

/* find end of headers */
int
httpMsgIsolateHeaders(const char **parse_start, const char **blk_start, const char **blk_end)
{
    /* adopted with mods from mime_headers_end() */
    const char *p1 = strstr(*parse_start, "\n\r\n");
    const char *p2 = strstr(*parse_start, "\n\n");
    const char *end = NULL;

    if (p1 && p2)
	end = p1 < p2 ? p1 : p2;
    else
	end = p1 ? p1 : p2;

    if (end) {
	*blk_start = *parse_start;
	*blk_end = end + 1;
	*parse_start = end + (end == p1 ? 3 : 2);
	return 1;
    }
    /* no headers, case 1 */
    if ((*parse_start)[0] == '\r' && (*parse_start)[1] == '\n') {
	*blk_start = *parse_start;
	*blk_end = *blk_start;
	*parse_start += 2;
	return 1;
    }
    /* no headers, case 2 */
    if ((*parse_start)[0] == '\n') {
	/* no headers */
	*blk_start = *parse_start;
	*blk_end = *blk_start;
	*parse_start += 1;
	return 1;
    }
    /* failure */
    return 0;
}

/* returns true if connection should be "persistent" after processing this message */
int
httpMsgIsPersistent(float http_ver, const HttpHeader *hdr)
{
    if (http_ver >= 1.1) {
	/* for modern versions of HTTP: persistent if not "close"d */
	return !httpHeaderHasConnDir(hdr, "close");
    } else {
	/* pconns in Netscape 3.x are allegedly broken, return false */
	const char *agent = httpHeaderGetStr(hdr, HDR_USER_AGENT);
	if (agent && (!strncasecmp(agent, "Mozilla/3.", 10) || !strncasecmp(agent, "Netscape/3.", 11)))
	    return 0;
	/* for old versions of HTTP: persistent if has "keep-alive" */
	return httpHeaderHasConnDir(hdr, "keep-alive");
    }
}
