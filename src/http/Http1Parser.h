#ifndef _SQUID_SRC_HTTP_ONEREQUESTPARSER_H
#define _SQUID_SRC_HTTP_ONEREQUESTPARSER_H

#include "base/RefCount.h"
#include "http/forward.h"
#include "http/ProtocolVersion.h"
#include "http/RequestMethod.h"
#include "http/StatusCode.h"
#include "SBuf.h"

namespace Http {
namespace One {

// Parser states
enum ParseState {
    HTTP_PARSE_NONE =0,  ///< nothing. completely unset state.
    HTTP_PARSE_NEW =1,   ///< initialized, but nothing usefully parsed yet
    HTTP_PARSE_FIRST,    ///< HTTP/1 message first line
    HTTP_PARSE_MIME,     ///< mime header block
    HTTP_PARSE_DONE      ///< completed with parsing a full request header
};

/** HTTP protocol parser.
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * either an error state or HTTP procotol major sections:
 *
 * \item first-line (request-line / simple-request / status-line)
 * \item mime-header block
 */
class Parser : public RefCountable
{
public:
    Parser() { clear(); }

    /** Initialize a new parser.
     * Presenting it a buffer to work on and the current length of available data.
     * NOTE: This is *not* the buffer size, just the parse-able data length.
     * The parse routines may be called again later with more data.
     */
    Parser(const char *aBuf, int len) { reset(aBuf,len); }

    /// Set this parser back to a default state.
    /// Will DROP any reference to a buffer (does not free).
    virtual void clear();

    /// Reset the parser for use on a new buffer.
    void reset(const char *aBuf, int len);

    /** Adjust parser state to account for a buffer shift of n bytes.
     *
     * The leftmost n bytes bytes have been dropped and all other
     * bytes shifted left n positions.
     */
    virtual void noteBufferShift(const int64_t n) = 0;

    /** Whether the parser is already done processing the buffer.
     * Use to determine between incomplete data and errors results
     * from the parse.
     */
    bool isDone() const {return parsingStage_==HTTP_PARSE_DONE;}

    /// number of bytes at the start of the buffer which are no longer needed
    int64_t doneBytes() const {return (int64_t)parseOffset_;}

    /// size in bytes of the first line including CRLF terminator
    virtual int64_t firstLineSize() const = 0;

    /// size in bytes of the message headers including CRLF terminator(s)
    /// but excluding first-line bytes
    int64_t headerBlockSize() const {return mimeHeaderBlock_.length();}

    /// size in bytes of HTTP message block, includes first-line and mime headers
    /// excludes any body/entity/payload bytes
    /// excludes any garbage prefix before the first-line
    int64_t messageHeaderSize() const {return firstLineSize() + headerBlockSize();}

    /// buffer containing HTTP mime headers, excluding message first-line.
    const char *rawHeaderBuf() {return mimeHeaderBlock_.c_str();}

    /// attempt to parse a message from the buffer
    /// \retval true if a full message was found and parsed
    /// \retval false if incomplete, invalid or no message was found
    virtual bool parse() = 0;

    /// the protocol label for this message
    const AnyP::ProtocolVersion & messageProtocol() const {return msgProtocol_;}

    /**
     * \return A pointer to a field-value of the first matching field-name, or NULL.
     */
    char *getHeaderField(const char *name);

public:
    const char *buf;
    int bufsiz;

protected:
    /// what stage the parser is currently up to
    ParseState parsingStage_;

    /// what protocol label has been found in the first line
    AnyP::ProtocolVersion msgProtocol_;

    /// byte offset for non-parsed region of the buffer
    size_t parseOffset_;

    /// buffer holding the mime headers
    SBuf mimeHeaderBlock_;
};

/** HTTP protocol request parser.
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * either an error state or, an HTTP procotol request major segments:
 *
 * \item Request Line (method, URL, protocol, version)
 * \item Mime header block
 */
class RequestParser : public Http1::Parser
{
public:
    /* Http::One::Parser API */
    RequestParser() : Parser() {}
    RequestParser(const char *aBuf, int len) : Parser(aBuf, len) {}
    virtual void clear();
    virtual void noteBufferShift(const int64_t n);
    virtual int64_t firstLineSize() const {return req.end - req.start + 1;}
    virtual bool parse();

    /// the HTTP method if this is a request message
    const HttpRequestMethod & method() const {return method_;}

    /// the request-line URI if this is a request message, or an empty string.
    const SBuf &requestUri() const {return uri_;}

    /** HTTP status code to be used on the invalid-request error page
     * Http::scNone indicates incomplete parse, Http::scOkay indicates no error.
     */
    Http::StatusCode request_parse_status;

private:
    void skipGarbageLines();
    int parseRequestFirstLine();

    /// Offsets for pieces of the (HTTP request) Request-Line as per RFC 2616
    /// only valid before and during parse stage HTTP_PARSE_FIRST
    struct request_offsets {
        int start, end;
        int m_start, m_end; // method
        int u_start, u_end; // url
        int v_start, v_end; // version (full text)
    } req;

    /// what request method has been found on the first line
    HttpRequestMethod method_;

    /// raw copy of the origina client reqeust-line URI field
    SBuf uri_;
};

} // namespace One
} // namespace Http

#endif /*  _SQUID_SRC_HTTP_HTTP1PARSER_H */
