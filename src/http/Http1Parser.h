#ifndef _SQUID_SRC_Http1Parser_H
#define _SQUID_SRC_Http1Parser_H

#include "base/RefCount.h"
#include "http/ProtocolVersion.h"
#include "http/StatusCode.h"

namespace Http {

// Parser states
#define HTTP_PARSE_NONE   0 // nothing. completely unset state.
#define HTTP_PARSE_NEW    1 // initialized, but nothing usefully parsed yet.
#define HTTP_PARSE_FIRST  2 // have parsed request first line
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

    /// size in bytes of the message headers including CRLF terminator
    /// but excluding request-line bytes
    int64_t headerBlockSize() const {return hdr_end - hdr_start + 1;}

    /// size in bytes of HTTP message block, includes request-line and mime headers
    /// excludes any body/entity/payload bytes
    int64_t messageHeaderSize() const {return hdr_end - req.start + 1;}

    /// buffer containing HTTP mime headers
    // convert to SBuf
    const char *rawHeaderBuf() {return buf + hdr_start;}

    /** Attempt to parse a request.
     * \return true if a valid request was parsed.
     * \note Use isDone() method to determine between incomplete parse and errors.
     */
    // TODO: parse more than just the request-line
    bool parseRequest();

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
     * \retval  1  successful parse. member fields contain the request-line items
     * \retval  0  more data is needed to complete the parse
     */
    int parseRequestFirstLine();

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

    // Offsets for pieces of the MiME Header segment
    int hdr_start, hdr_end;

    // TODO: Offsets for pieces of the (HTTP reply) Status-Line as per RFC 2616

    /** HTTP status code to be used on the invalid-request error page
     * Http::scNone indicates incomplete parse, Http::scOkay indicates no error.
     */
    Http::StatusCode request_parse_status;

private:
    /// byte offset for non-parsed region of the buffer
    size_t parseOffset_;

    /// what stage the parser is currently up to
    uint8_t completedState_;

    /// what protocol label has been found in the first line
    AnyP::ProtocolVersion msgProtocol_;
};

} // namespace Http

#endif /*  _SQUID_SRC_Http1Parser_H */
