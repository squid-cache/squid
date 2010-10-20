/*
 * $Id$
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

#if DEAD_CODE
/** do everything in one call: init, set, pack, clean, return MemBuf */
extern MemBuf *httpPackedReply(HttpVersion ver, http_status status, const char *ctype, int64_t clen, time_t lmt, time_t expires);
#endif

/* Sync changes here with HttpReply.cc */

class HttpHdrContRange;

class HttpHdrSc;

class HttpReply: public HttpMsg
{

public:
    typedef HttpMsgPointerT<HttpReply> Pointer;

    MEMPROXY_CLASS(HttpReply);
    HttpReply();
    ~HttpReply();

    virtual void reset();

    /// \par use HTTPMSGLOCK() instead of calling this directly
    virtual HttpReply *_lock() {
        return static_cast<HttpReply*>(HttpMsg::_lock());
    };

    //virtual void unlock();  // only needed for debugging

    /**
     \retval true on success
     \retval false and sets *error to zero when needs more data
     \retval false and sets *error to a positive http_status code on error
     */
    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error);

    /** \par public, readable; never update these or their .hdr equivalents directly */
    time_t date;

    time_t last_modified;

    time_t expires;

    String content_type;

    HttpHdrSc *surrogate_control;

    HttpHdrContRange *content_range;

    short int keep_alive;

    /** \par public, writable, but use httpReply* interfaces when possible */
    HttpStatusLine sline;

    HttpBody body;		/**< for small constant memory-resident text bodies only */

    String protoPrefix;         /**< e.g., "HTTP/"  */

    bool do_clean;

public:
    virtual int httpMsgParseError();

    virtual bool expectingBody(const HttpRequestMethod&, int64_t&) const;

    virtual bool inheritProperties(const HttpMsg *aMsg);

    void updateOnNotModified(HttpReply const *other);

    /** set commonly used info with one call */
    void setHeaders(http_status status,
                    const char *reason, const char *ctype, int64_t clen, time_t lmt, time_t expires);

    /** \return a ready to use mem buffer with a packed reply */
    MemBuf *pack();

    /** construct a 304 reply and return it */
    HttpReply *make304() const;

    void redirect(http_status, const char *);

    int64_t bodySize(const HttpRequestMethod&) const;

    /** Checks whether received body exceeds known maximum size.
     * Requires a prior call to calcMaxBodySize().
     */
    bool receivedBodyTooLarge(HttpRequest&, int64_t receivedBodySize);

    /** Checks whether expected body exceeds known maximum size.
     * Requires a prior call to calcMaxBodySize().
     */
    bool expectedBodyTooLarge(HttpRequest& request);

    int validatorsMatch (HttpReply const *other) const;

    void packHeadersInto(Packer * p) const;

    /** Clone this reply.
     *  Could be done as a copy-contructor but we do not want to accidently copy a HttpReply..
     */
    HttpReply *clone() const;

    /// Remove Warnings with warn-date different from Date value
    void removeStaleWarnings();

private:
    /** initialize */
    void init();

    void clean();

    void hdrCacheClean();

    void packInto(Packer * p);

    /* ez-routines */
    /** \return construct 304 reply and pack it into a MemBuf */
    MemBuf *packed304Reply();

    /* header manipulation */
    time_t hdrExpirationTime();

    /** Calculates and stores maximum body size if needed.
     * Used by receivedBodyTooLarge() and expectedBodyTooLarge().
     */
    void calcMaxBodySize(HttpRequest& request);

    String removeStaleWarningValues(const String &value);

    mutable int64_t bodySizeMax; /**< cached result of calcMaxBodySize */

protected:
    virtual void packFirstLineInto(Packer * p, bool) const;

    virtual bool parseFirstLine(const char *start, const char *end);

    virtual void hdrCacheInit();
};

MEMPROXY_CLASS_INLINE(HttpReply);

#endif /* SQUID_HTTPREPLY_H */
