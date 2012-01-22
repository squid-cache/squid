#include "squid.h"
#include "HttpReply.h"

#define STUB_API "HttpReply.cc"
#include "tests/STUB.h"

HttpReply::HttpReply() : HttpMsg(hoReply)
{
// XXX: required by testStore
// STUB
}
HttpReply::~HttpReply() STUB
void HttpReply::setHeaders(http_status status, const char *reason, const char *ctype, int64_t clen, time_t lmt, time_t expires_) STUB
void HttpReply::packHeadersInto(Packer * p) const STUB
void HttpReply::reset() STUB
void httpBodyPackInto(const HttpBody * body, Packer * p) STUB
bool HttpReply::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error) STUB_RETVAL(false)
int HttpReply::httpMsgParseError() STUB_RETVAL(0)
bool HttpReply::expectingBody(const HttpRequestMethod&, int64_t&) const STUB_RETVAL(false)
void HttpReply::packFirstLineInto(Packer * p, bool) const STUB
bool HttpReply::parseFirstLine(const char *start, const char *end) STUB_RETVAL(false)
void HttpReply::hdrCacheInit() STUB
HttpReply * HttpReply::clone() const STUB_RETVAL(NULL)
bool HttpReply::inheritProperties(const HttpMsg *aMsg) STUB_RETVAL(false)
int64_t HttpReply::bodySize(const HttpRequestMethod&) const STUB_RETVAL(0)
