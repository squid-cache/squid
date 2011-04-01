
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

#ifndef SQUID_HTTPMSG_H
#define SQUID_HTTPMSG_H

#include "typedefs.h"
#include "HttpHeader.h"
#include "HttpStatusCode.h"
#include "HttpVersion.h"
#include "BodyPipe.h"

// common parts of HttpRequest and HttpReply

template <class Msg>
class HttpMsgPointerT;


class HttpMsg
{

public:
    typedef HttpMsgPointerT<HttpMsg> Pointer;

    HttpMsg(http_hdr_owner_type owner);
    virtual ~HttpMsg();

    virtual void reset() = 0; // will have body when http*Clean()s are gone

    void packInto(Packer * p, bool full_uri) const;

    virtual HttpMsg *_lock();	// please use HTTPMSGLOCK()
    virtual void _unlock();	// please use HTTPMSGUNLOCK()

    ///< produce a message copy, except for a few connection-specific settings
    virtual HttpMsg *clone() const = 0; ///< \todo rename: not a true copy?

    /// [re]sets Content-Length header and cached value
    void setContentLength(int64_t clen);

public:
    HttpVersion http_ver;

    HttpHeader header;

    HttpHdrCc *cache_control;

    /* Unsupported, writable, may disappear/change in the future
     * For replies, sums _stored_ status-line, headers, and <CRLF>.
     * Also used to report parsed header size if parse() is successful */
    int hdr_sz;

    int64_t content_length;

    protocol_t protocol;

    HttpMsgParseState pstate;   /* the current parsing state */

    BodyPipe::Pointer body_pipe; // optional pipeline to receive message body

    // returns true and sets hdr_sz on success
    // returns false and sets *error to zero when needs more data
    // returns false and sets *error to a positive http_status code on error
    bool parse(MemBuf *buf, bool eol, http_status *error);

    bool parseCharBuf(const char *buf, ssize_t end);

    int httpMsgParseStep(const char *buf, int len, int atEnd);

    virtual int httpMsgParseError();

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
    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error) = 0;

    virtual void packFirstLineInto(Packer * p, bool full_uri) const = 0;

    virtual bool parseFirstLine(const char *blk_start, const char *blk_end) = 0;

    virtual void hdrCacheInit();

    int lock_count;

};

/* Temporary parsing state; might turn into the replacement parser later on */
class HttpParser
{
public:
    /**
     * Attempt to parse the first line of a new request message.
     *
     * Governed by:
     *  RFC 1945 section 5.1
     *  RFC 2616 section 5.1
     *
     * Parsing state is stored between calls. However the current implementation
     * begins parsing from scratch on every call.
     * The return value tells you whether the parsing state fields are valid or not.
     *
     * \retval -1  an error occurred. request_parse_status indicates HTTP status result.
     * \retval  1  successful parse
     * \retval  0  more data is needed to complete the parse
     */
    int parseRequestFirstLine();

public:
    char state;
    const char *buf;
    int bufsiz;
    int req_start, req_end;
    int hdr_start, hdr_end;
    int m_start, m_end;
    int u_start, u_end;
    int v_start, v_end;
    int v_maj, v_min;
};

extern void HttpParserInit(HttpParser *, const char *buf, int len);
extern int HttpParserParseReqLine(HttpParser *hp);

#define MSGDODEBUG 0
#if MSGDODEBUG
extern int HttpParserReqSz(HttpParser *);
extern int HttpParserHdrSz(HttpParser *);
extern const char * HttpParserHdrBuf(HttpParser *);
extern int HttpParserRequestLen(HttpParser *hp);
#else
#define	HttpParserReqSz(hp)	( (hp)->req_end - (hp)->req_start + 1 )
#define	HttpParserHdrSz(hp)	( (hp)->hdr_end - (hp)->hdr_start + 1 )
#define	HttpParserHdrBuf(hp)	( (hp)->buf + (hp)->hdr_start )
#define	HttpParserRequestLen(hp)	( (hp)->hdr_end - (hp)->req_start + 1 )
#endif

SQUIDCEXTERN int httpMsgIsolateHeaders(const char **parse_start, int len, const char **blk_start, const char **blk_end);

#define HTTPMSGUNLOCK(a) if(a){(a)->_unlock();(a)=NULL;}
#define HTTPMSGLOCK(a) (a)->_lock()

// TODO: replace HTTPMSGLOCK with general RefCounting and delete this class
/// safe HttpMsg pointer wrapper that locks and unlocks the message
template <class Msg>
class HttpMsgPointerT
{
public:
    HttpMsgPointerT(): msg(NULL) {}
    explicit HttpMsgPointerT(Msg *m): msg(m) { lock(); }
    virtual ~HttpMsgPointerT() { unlock(); }

    HttpMsgPointerT(const HttpMsgPointerT &p): msg(p.msg) { lock(); }
    HttpMsgPointerT &operator =(const HttpMsgPointerT &p)
    { if (msg != p.msg) { unlock(); msg = p.msg; lock(); } return *this; }
    HttpMsgPointerT &operator =(Msg *newM)
    { if (msg != newM) { unlock(); msg = newM; lock(); } return *this; }

    /// support converting a child msg pointer into a parent msg pointer
    template <typename Other>
    HttpMsgPointerT(const HttpMsgPointerT<Other> &o): msg(o.raw()) { lock(); }

    /// support assigning a child msg pointer to a parent msg pointer
    template <typename Other>
    HttpMsgPointerT &operator =(const HttpMsgPointerT<Other> &o)
    { if (msg != o.raw()) { unlock(); msg = o.raw(); lock(); } return *this; }

    Msg &operator *() { return *msg; }
    const Msg &operator *() const { return *msg; }
    Msg *operator ->() { return msg; }
    const Msg *operator ->() const { return msg; }
    operator Msg *() const { return msg; }
    // add more as needed

    /// public access for HttpMsgPointerT copying and assignment; avoid
    Msg *raw() const { return msg; }

protected:
    void lock() { if (msg) HTTPMSGLOCK(msg); } ///< prevent msg destruction
    void unlock() { HTTPMSGUNLOCK(msg); } ///< allows/causes msg destruction

private:
    Msg *msg;
};

/// convenience wrapper to create HttpMsgPointerT<> object based on msg type
template <class Msg>
inline
HttpMsgPointerT<Msg> HttpMsgPointer(Msg *msg)
{
    return HttpMsgPointerT<Msg>(msg);
}

#endif /* SQUID_HTTPMSG_H */
