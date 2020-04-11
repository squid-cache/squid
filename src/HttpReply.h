/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPREPLY_H
#define SQUID_HTTPREPLY_H

#include "http/StatusLine.h"
#include "HttpBody.h"
#include "HttpRequest.h"

void httpReplyInitModule(void);

/* Sync changes here with HttpReply.cc */

class HttpHdrContRange;

class HttpHdrSc;

class HttpReply: public Http::Message
{
    MEMPROXY_CLASS(HttpReply);

public:
    typedef RefCount<HttpReply> Pointer;

    HttpReply();
    ~HttpReply();

    virtual void reset();

    /**
     \retval true on success
     \retval false and sets *error to zero when needs more data
     \retval false and sets *error to a positive Http::StatusCode on error
     */
    virtual bool sanityCheckStartLine(const char *buf, const size_t hdr_len, Http::StatusCode *error);

    /** \par public, readable; never update these or their .hdr equivalents directly */
    time_t date;

    time_t last_modified;

    time_t expires;

    String content_type;

    HttpHdrSc *surrogate_control;

    /// \returns parsed Content-Range for a 206 response and nil for others
    const HttpHdrContRange *contentRange() const;

    short int keep_alive;

    /** \par public, writable, but use httpReply* interfaces when possible */
    Http::StatusLine sline;

    HttpBody body;      /**< for small constant memory-resident text bodies only */

    String protoPrefix;         /**< e.g., "HTTP/"  */

    bool do_clean;

public:
    virtual int httpMsgParseError();

    virtual bool expectingBody(const HttpRequestMethod&, int64_t&) const;

    virtual bool inheritProperties(const Http::Message *);

    /// \returns nil (if no updates are necessary)
    /// \returns a new reply combining this reply with 304 updates (otherwise)
    Pointer recreateOnNotModified(const HttpReply &reply304) const;

    /** set commonly used info with one call */
    void setHeaders(Http::StatusCode status,
                    const char *reason, const char *ctype, int64_t clen, time_t lmt, time_t expires);

    /** \return a ready to use mem buffer with a packed reply */
    MemBuf *pack() const;

    /// construct and return an HTTP/200 (Connection Established) response
    static HttpReplyPointer MakeConnectionEstablished();

    /** construct a 304 reply and return it */
    HttpReplyPointer make304() const;

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

    /// adds status line and header to the given Packable
    /// assumes that `p` can quickly process small additions
    void packHeadersUsingFastPacker(Packable &p) const;
    /// same as packHeadersUsingFastPacker() but assumes that `p` cannot quickly process small additions
    void packHeadersUsingSlowPacker(Packable &p) const;

    /** Clone this reply.
     *  Could be done as a copy-contructor but we do not want to accidentally copy a HttpReply..
     */
    HttpReply *clone() const;

    /// Remove Warnings with warn-date different from Date value
    void removeStaleWarnings();

    virtual void hdrCacheInit();

    /// whether our Date header value is smaller than theirs
    /// \returns false if any information is missing
    bool olderThan(const HttpReply *them) const;

    /// Some response status codes prohibit sending Content-Length (RFC 7230 section 3.3.2).
    void removeIrrelevantContentLength();

    virtual void configureContentLengthInterpreter(Http::ContentLengthInterpreter &);
    /// parses reply header using Parser
    bool parseHeader(Http1::Parser &hp);

private:
    /** initialize */
    void init();

    void clean();

    void hdrCacheClean();

    void packInto(MemBuf &) const;

    /* ez-routines */
    /** \return construct 304 reply and pack it into a MemBuf */
    MemBuf *packed304Reply() const;

    /* header manipulation */
    time_t hdrExpirationTime();

    /** Calculates and stores maximum body size if needed.
     * Used by receivedBodyTooLarge() and expectedBodyTooLarge().
     */
    void calcMaxBodySize(HttpRequest& request) const;

    String removeStaleWarningValues(const String &value);

    mutable int64_t bodySizeMax; /**< cached result of calcMaxBodySize */

    HttpHdrContRange *content_range; ///< parsed Content-Range; nil for non-206 responses!

protected:
    virtual void packFirstLineInto(Packable * p, bool) const { sline.packInto(p); }

    virtual bool parseFirstLine(const char *start, const char *end);
};

#endif /* SQUID_HTTPREPLY_H */

