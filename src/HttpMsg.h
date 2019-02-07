/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPMSG_H
#define SQUID_HTTPMSG_H

#include "base/Lock.h"
#include "BodyPipe.h"
#include "enums.h"
#include "http/forward.h"
#include "http/ProtocolVersion.h"
#include "http/StatusCode.h"
#include "HttpHeader.h"

/// common parts of HttpRequest and HttpReply
class HttpMsg : public RefCountable
{

public:
    typedef RefCount<HttpMsg> Pointer;
    /// Who may have created or modified this message?
    enum Sources {
        srcUnknown = 0,

        /* flags in 0xFFFF zone are for "secure" or "encrypted" sources */
        srcHttps = 1 << 0, ///< https_port or bumped http_port tunnel; HTTPS server
        srcFtps = 1 << 1, ///< ftps_port or SFTP server; currently unused
        srcIcaps = 1 << 2, ///< Secure ICAP service
        srcEcaps = 1 << 3, ///< eCAP service that is considered secure; currently unused

        /* these flags "taint" the message: it may have been observed or mangled outside Squid */
        srcHttp = 1 << (16 + 0), ///< http_port or HTTP server
        srcFtp = 1 << (16 + 1), ///< ftp_port or FTP server
        srcIcap = 1 << (16 + 2), ///< traditional ICAP service without encryption
        srcEcap = 1 << (16 + 3), ///< eCAP service that uses insecure libraries/daemons
        srcGopher = 1 << (16 + 14), ///< Gopher server
        srcWhois = 1 << (16 + 15), ///< Whois server
        srcUnsafe = 0xFFFF0000,  ///< Unsafe sources mask
        srcSafe = 0x0000FFFF ///< Safe sources mask
    };

    HttpMsg(http_hdr_owner_type owner);
    virtual ~HttpMsg();

    virtual void reset() = 0; // will have body when http*Clean()s are gone

    void packInto(Packable * p, bool full_uri) const;

    ///< produce a message copy, except for a few connection-specific settings
    virtual HttpMsg *clone() const = 0; ///< \todo rename: not a true copy?

    /// [re]sets Content-Length header and cached value
    void setContentLength(int64_t clen);

    /**
     * \retval true  the message sender asks to keep the connection open.
     * \retval false the message sender will close the connection.
     *
     * Factors other than the headers may result in connection closure.
     */
    bool persistent() const;

public:
    /// HTTP-Version field in the first line of the message.
    /// see RFC 7230 section 3.1
    AnyP::ProtocolVersion http_ver;

    HttpHeader header;

    HttpHdrCc *cache_control;

    /* Unsupported, writable, may disappear/change in the future
     * For replies, sums _stored_ status-line, headers, and <CRLF>.
     * Also used to report parsed header size if parse() is successful */
    int hdr_sz;

    int64_t content_length;

    HttpMsgParseState pstate;   /* the current parsing state */

    BodyPipe::Pointer body_pipe; // optional pipeline to receive message body

    uint32_t sources; ///< The message sources

    /// copies Cache-Control header to this message
    void putCc(const HttpHdrCc *otherCc);

    // returns true and sets hdr_sz on success
    // returns false and sets *error to zero when needs more data
    // returns false and sets *error to a positive Http::StatusCode on error
    bool parse(const char *buf, const size_t sz, bool eol, Http::StatusCode *error);

    bool parseCharBuf(const char *buf, ssize_t end);

    int httpMsgParseStep(const char *buf, int len, int atEnd);

    virtual int httpMsgParseError();

    // Parser-NG transitional parsing of mime headers
    bool parseHeader(Http1::Parser &); // TODO move this function to the parser

    virtual bool expectingBody(const HttpRequestMethod&, int64_t&) const = 0;

    void firstLineBuf(MemBuf&);

    virtual bool inheritProperties(const HttpMsg *aMsg) = 0;

protected:
    /**
     * Validate the message start line is syntactically correct.
     * Set HTTP error status according to problems found.
     *
     * \retval true   Status line has no serious problems.
     * \retval false  Status line has a serious problem. Correct response is indicated by error.
     */
    virtual bool sanityCheckStartLine(const char *buf, const size_t hdr_len, Http::StatusCode *error) = 0;

    virtual void packFirstLineInto(Packable * p, bool full_uri) const = 0;

    virtual bool parseFirstLine(const char *blk_start, const char *blk_end) = 0;

    virtual void hdrCacheInit();
};

#define HTTPMSGUNLOCK(a) if (a) { if ((a)->unlock() == 0) delete (a); (a)=NULL; }
#define HTTPMSGLOCK(a) if (a) { (a)->lock(); }

#endif /* SQUID_HTTPMSG_H */

