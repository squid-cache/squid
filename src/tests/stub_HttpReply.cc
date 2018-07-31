/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "HttpReply.h"

#define STUB_API "HttpReply.cc"
#include "tests/STUB.h"

HttpReply::HttpReply() : Http::Message(hoReply), date (0), last_modified (0),
    expires(0), surrogate_control(nullptr), keep_alive(0),
    protoPrefix("HTTP/"), do_clean(false), bodySizeMax(-2), content_range(nullptr)
{STUB_NOP}
HttpReply::~HttpReply() STUB
void HttpReply::setHeaders(Http::StatusCode status, const char *reason, const char *ctype, int64_t clen, time_t lmt, time_t expires_) STUB
void HttpReply::packHeadersUsingFastPacker(Packable&) const STUB
void HttpReply::packHeadersUsingSlowPacker(Packable&) const STUB
void HttpReply::reset() STUB
void httpBodyPackInto(const HttpBody *, Packable *) STUB
bool HttpReply::sanityCheckStartLine(const char *buf, const size_t hdr_len, Http::StatusCode *error) STUB_RETVAL(false)
int HttpReply::httpMsgParseError() STUB_RETVAL(0)
bool HttpReply::expectingBody(const HttpRequestMethod&, int64_t&) const STUB_RETVAL(false)
bool HttpReply::parseFirstLine(const char *start, const char *end) STUB_RETVAL(false)
void HttpReply::hdrCacheInit() STUB
HttpReply * HttpReply::clone() const STUB_RETVAL(NULL)
bool HttpReply::inheritProperties(const Http::Message *aMsg) STUB_RETVAL(false)
bool HttpReply::updateOnNotModified(HttpReply const*) STUB_RETVAL(false)
int64_t HttpReply::bodySize(const HttpRequestMethod&) const STUB_RETVAL(0)
const HttpHdrContRange *HttpReply::contentRange() const STUB_RETVAL(nullptr)

