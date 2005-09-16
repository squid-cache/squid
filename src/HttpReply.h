
/*
 * $Id: HttpReply.h,v 1.11 2005/09/15 20:19:41 wessels Exp $
 *
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

#ifndef SQUID_HTTPREPLY_H
#define SQUID_HTTPREPLY_H

#include "HttpMsg.h"
#include "HttpStatusLine.h"

/* Http Reply */
extern void httpReplyInitModule(void);
/* create/destroy */
extern HttpReply *httpReplyCreate(void);
extern void httpReplyDestroy(HttpReply * rep);
/* reset: clean, then init */
extern void httpReplyReset(HttpReply * rep);
/* absorb: copy the contents of a new reply to the old one, destroy new one */
extern void httpReplyAbsorb(HttpReply * rep, HttpReply * new_rep);
/* parse returns true on success */
extern bool httpReplyParse(HttpReply * rep, const char *buf, ssize_t);
extern void httpReplyPackHeadersInto(const HttpReply * rep, Packer * p);
extern void httpReplyPackInto(const HttpReply * rep, Packer * p);
/* ez-routines */
/* mem-pack: returns a ready to use mem buffer with a packed reply */
extern MemBuf *httpReplyPack(const HttpReply * rep);
/* swap: create swap-based packer, pack, destroy packer */
extern void httpReplySwapOut(HttpReply * rep, StoreEntry * e);
/* set commonly used info with one call */
extern void httpReplySetHeaders(HttpReply * rep, HttpVersion ver, http_status status,
                                    const char *reason, const char *ctype, int clen, time_t lmt, time_t expires);
/* do everything in one call: init, set, pack, clean, return MemBuf */
extern MemBuf *httpPackedReply(HttpVersion ver, http_status status, const char *ctype,
                                   int clen, time_t lmt, time_t expires);
/* construct 304 reply and pack it into MemBuf, return MemBuf */
extern MemBuf *httpPacked304Reply(const HttpReply * rep);
/* construct a 304 reply and return it */
extern HttpReply *httpReplyMake304(const HttpReply *rep);
/* header manipulation */
extern int httpReplyContentLen(const HttpReply * rep);
extern const char *httpReplyContentType(const HttpReply * rep);
extern time_t httpReplyExpires(const HttpReply * rep);
extern int httpReplyHasCc(const HttpReply * rep, http_hdr_cc_type type);
extern void httpRedirectReply(HttpReply *, http_status, const char *);
extern int httpReplyBodySize(method_t, HttpReply const *);
extern int httpReplyValidatorsMatch (HttpReply const *, HttpReply const *);


/* Sync changes here with HttpReply.cc */

class HttpHdrContRange;

class HttpReply: public HttpMsg
{

public:
    MEMPROXY_CLASS(HttpReply);
    HttpReply();

    virtual void reset();

    // returns true on success
    // returns false and sets *error to zero when needs more data
    // returns false and sets *error to a positive http_status code on error
    virtual bool sanityCheckStartLine(MemBuf *buf, http_status *error);

    /* public, readable; never update these or their .hdr equivalents directly */
    time_t date;
    time_t last_modified;
    time_t expires;
    String content_type;
    HttpHdrSc *surrogate_control;
    HttpHdrContRange *content_range;
    short int keep_alive;

    /* public, writable, but use httpReply* interfaces when possible */
    HttpStatusLine sline;
    HttpBody body;		/* for small constant memory-resident text bodies only */

    String protoPrefix;       // e.g., "HTTP/"

public:
    void httpReplyUpdateOnNotModified(HttpReply const *other);

protected:
    virtual void packFirstLineInto(Packer * p, bool) const;
    virtual bool parseFirstLine(const char *start, const char *end);
    virtual void hdrCacheInit();
};

MEMPROXY_CLASS_INLINE(HttpReply)

#endif /* SQUID_HTTPREPLY_H */
