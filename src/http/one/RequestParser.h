#ifndef _SQUID_SRC_HTTP_ONE_REQUESTPARSER_H
#define _SQUID_SRC_HTTP_ONE_REQUESTPARSER_H

#include "http/one/Parser.h"
#include "http/RequestMethod.h"
#include "http/StatusCode.h"

namespace Http {
namespace One {

/** HTTP/1.x protocol request parser
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the major CRLF delimited segments of an HTTP/1 request message:
 *
 * \item request-line (method, URL, protocol, version)
 * \item mime-header (set of RFC2616 syntax header fields)
 */
class RequestParser : public Http1::Parser
{
    explicit RequestParser(const RequestParser&); // do not implement
    RequestParser& operator =(const RequestParser&); // do not implement

public:
    /* Http::One::Parser API */
    RequestParser() : Parser() {clear();}
    virtual ~RequestParser() {}
    virtual void clear();
    virtual int64_t firstLineSize() const {return req.end - req.start + 1;}
    virtual bool parse(const SBuf &aBuf);

    /// the HTTP method if this is a request message
    const HttpRequestMethod & method() const {return method_;}

    /// the request-line URI if this is a request message, or an empty string.
    const SBuf &requestUri() const {return uri_;}

    /** HTTP status code to be used on the invalid-request error page.
     * Http::scNone indicates incomplete parse,
     * Http::scOkay indicates no error.
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

#endif /*  _SQUID_SRC_HTTP_ONE_REQUESTPARSER_H */
