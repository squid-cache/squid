#ifndef _SQUID_SRC_HTTP_HTTP1PARSER_H
#define _SQUID_SRC_HTTP_HTTP1PARSER_H

#include "base/RefCount.h"
#include "http/forward.h"
#include "http/ProtocolVersion.h"
#include "http/StatusCode.h"
#include "SBuf.h"

namespace Http {

// Parser states
#define HTTP_PARSE_NONE   0 // nothing. completely unset state.
#define HTTP_PARSE_NEW    1 // initialized, but nothing usefully parsed yet.
#define HTTP_PARSE_FIRST  2 // have parsed request first line
#define HTTP_PARSE_MIME   3 // have located end of mime header block
#define HTTP_PARSE_DONE   99 // have done with parsing so far

/** HTTP protocol parser.
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * either an error state or, an HTTP procotol request major segments:
 *
 * \item Request Line (method, URL, protocol, version)
 * \item Mime header block
 */
class Http1Parser : public RefCountable
{
public:
    typedef RefCount<Http1Parser> Pointer;

    Http1Parser() { clear(); }

    /** Initialize a new parser.
     * Presenting it a buffer to work on and the current length of available
     * data.
     * NOTE: This is *not* the buffer size, just the parse-able data length.
     * The parse routines may be called again later with more data.
     */
    Http1Parser(const char *aBuf, int len) { reset(aBuf,len); };

    /// Set this parser back to a default state.
    /// Will DROP any reference to a buffer (does not free).
    void clear();

    /// Reset the parser for use on a new buffer.
    void reset(const char *aBuf, int len);

    /** Whether the parser is already done processing the buffer.
     * Use to determine between incomplete data and errors results
     * from the parse methods.
     */
    bool isDone() const {return completedState_==HTTP_PARSE_DONE;}

    /// size in bytes of the first line (request-line)
    /// including CRLF terminator
    int64_t firstLineSize() const {return req.end - req.start + 1;}

    /// size in bytes of the message headers including CRLF terminator(s)
    /// but excluding request-line bytes
    int64_t headerBlockSize() const {return mimeHeaderBlock_.length();}

    /// size in bytes of HTTP message block, includes request-line and mime headers
    /// excludes any body/entity/payload bytes
    /// excludes any garbage prefix before the request-line
    int64_t messageHeaderSize() const {return firstLineSize() + headerBlockSize();}

    /// buffer containing HTTP mime headers, excluding request or status line.
    const char *rawHeaderBuf() {return mimeHeaderBlock_.c_str();}

    /** Attempt to parse a request.
     * \return true if a valid request was parsed.
     * \note Use isDone() method to determine between incomplete parse and errors.
     */
    bool parseRequest();

    /**
     * \return A pointer to a field-value of the first matching field-name, or NULL.
     */
    char *getHeaderField(const char *name);

public:
    const char *buf;
    int bufsiz;

    /// Offsets for pieces of the (HTTP request) Request-Line as per RFC 2616
    struct request_offsets {
        int start, end;
        int m_start, m_end; // method
        int u_start, u_end; // url
        int v_start, v_end; // version (full text)
    } req;

    /// the protocol label for this message
    const AnyP::ProtocolVersion & messageProtocol() const {return msgProtocol_;}

    /// the HTTP method if this is a request method
    const HttpRequestMethodPointer & method() const {return method_;}

    /// the request-line URI if this is a request, or an empty string.
    SBuf requestUri() const {return uri_;}

    // TODO: Offsets for pieces of the (HTTP reply) Status-Line as per RFC 2616

    /** HTTP status code to be used on the invalid-request error page
     * Http::scNone indicates incomplete parse, Http::scOkay indicates no error.
     */
    Http::StatusCode request_parse_status;

private:
    bool skipGarbageLines();
    int parseRequestFirstLine();

    /// byte offset for non-parsed region of the buffer
    size_t parseOffset_;

    /// what stage the parser is currently up to
    uint8_t completedState_;

    /// what protocol label has been found in the first line
    AnyP::ProtocolVersion msgProtocol_;

    /// what request method has been found on the first line
    HttpRequestMethodPointer method_;

    /// raw copy of the origina client reqeust-line URI field
    SBuf uri_;

    /// buffer holding the mime headers
    SBuf mimeHeaderBlock_;
};

} // namespace Http

#endif /*  _SQUID_SRC_HTTP_HTTP1PARSER_H */
