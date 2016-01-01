/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPREPLY_H
#define SQUID_HTTPREPLY_H

#include "http/StatusLine.h"
#include "HttpBody.h"
#include "HttpMsg.h"
#include "HttpRequest.h"

void httpReplyInitModule(void);

/* Sync changes here with HttpReply.cc */

class HttpHdrContRange;

class HttpHdrSc;

class HttpReply: public HttpMsg
{

public:
    typedef RefCount<HttpReply> Pointer;

    MEMPROXY_CLASS(HttpReply);
    HttpReply();
    ~HttpReply();

    virtual void reset();

    /**
     \retval true on success
     \retval false and sets *error to zero when needs more data
     \retval false and sets *error to a positive Http::StatusCode on error
     */
    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error);

    /** \par public, readable; never update these or their .hdr equivalents directly */
    time_t date;

    time_t last_modified;

    time_t expires;

    String content_type;

    HttpHdrSc *surrogate_control;

    HttpHdrContRange *content_range;

    short int keep_alive;

    /** \par public, writable, but use httpReply* interfaces when possible */
    Http::StatusLine sline;

    HttpBody body;      /**< for small constant memory-resident text bodies only */

    String protoPrefix;         /**< e.g., "HTTP/"  */

    bool do_clean;

public:
    virtual int httpMsgParseError();

    virtual bool expectingBody(const HttpRequestMethod&, int64_t&) const;

    virtual bool inheritProperties(const HttpMsg *aMsg);

    void updateOnNotModified(HttpReply const *other);

    /** set commonly used info with one call */
    void setHeaders(Http::StatusCode status,
                    const char *reason, const char *ctype, int64_t clen, time_t lmt, time_t expires);

    /** \return a ready to use mem buffer with a packed reply */
    MemBuf *pack();

    /** construct a 304 reply and return it */
    HttpReply *make304() const;

    void redirect(Http::StatusCode, const char *);

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

    virtual void hdrCacheInit();

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
    void calcMaxBodySize(HttpRequest& request) const;

    String removeStaleWarningValues(const String &value);

    mutable int64_t bodySizeMax; /**< cached result of calcMaxBodySize */

protected:
    virtual void packFirstLineInto(Packer * p, bool) const { sline.packInto(p); }

    virtual bool parseFirstLine(const char *start, const char *end);
};

MEMPROXY_CLASS_INLINE(HttpReply);

#endif /* SQUID_HTTPREPLY_H */

