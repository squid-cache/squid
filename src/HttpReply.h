
/*
 * $Id: HttpReply.h,v 1.21 2007/08/13 17:20:51 hno Exp $
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

extern void httpReplyInitModule(void);
/* do everything in one call: init, set, pack, clean, return MemBuf */
extern MemBuf *httpPackedReply(HttpVersion ver, http_status status, const char *ctype, int64_t clen, time_t lmt, time_t expires);

/* Sync changes here with HttpReply.cc */

class HttpHdrContRange;

class HttpHdrSc;

class HttpReply: public HttpMsg
{

public:
    MEMPROXY_CLASS(HttpReply);
    HttpReply();
    ~HttpReply();

    virtual void reset();

    // use HTTPMSGLOCK() instead of calling this directly
    virtual HttpReply *_lock()
    {
        return static_cast<HttpReply*>(HttpMsg::_lock());
    };

    //virtual void unlock();  // only needed for debugging

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

    bool do_clean;

public:
    virtual int httpMsgParseError();

    virtual bool expectingBody(method_t, int64_t&) const;

    void updateOnNotModified(HttpReply const *other);

    /* absorb: copy the contents of a new reply to the old one, destroy new one */
    void absorb(HttpReply * new_rep);

    /* set commonly used info with one call */
    void setHeaders(HttpVersion ver, http_status status,
                    const char *reason, const char *ctype, int64_t clen, time_t lmt, time_t expires);

    /* mem-pack: returns a ready to use mem buffer with a packed reply */
    MemBuf *pack();

    /* construct a 304 reply and return it */
    HttpReply *make304() const;

    void redirect(http_status, const char *);

    int64_t bodySize(method_t) const;

    int validatorsMatch (HttpReply const *other) const;

    void packHeadersInto(Packer * p) const;

private:
    /* initialize */
    void init();

    void clean();

    void hdrCacheClean();

    void packInto(Packer * p);

    /* ez-routines */
    /* construct 304 reply and pack it into MemBuf, return MemBuf */
    MemBuf *packed304Reply();

    /* header manipulation */
    time_t hdrExpirationTime();

protected:
    virtual void packFirstLineInto(Packer * p, bool) const;

    virtual bool parseFirstLine(const char *start, const char *end);

    virtual void hdrCacheInit();
};

MEMPROXY_CLASS_INLINE(HttpReply)

#endif /* SQUID_HTTPREPLY_H */
