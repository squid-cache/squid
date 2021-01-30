/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpRequest.h"

#define STUB_API "HttpRequest.cc"
#include "tests/STUB.h"

// void httpRequestPack(void *obj, Packable *p);

HttpRequest::HttpRequest(const MasterXaction::Pointer&) : HttpMsg(hoRequest) {STUB}
HttpRequest::HttpRequest(const HttpRequestMethod &, AnyP::ProtocolType, const char *, const char *, const MasterXaction::Pointer &) : HttpMsg(hoRequest) {STUB}
HttpRequest::~HttpRequest() STUB
void HttpRequest::reset() STUB
void HttpRequest::initHTTP(const HttpRequestMethod &, AnyP::ProtocolType, const char *, const char *) STUB
HttpRequest * HttpRequest::clone() const STUB_RETVAL(NULL)
bool HttpRequest::maybeCacheable() STUB_RETVAL(false)
bool HttpRequest::conditional() const STUB_RETVAL(false)
bool HttpRequest::canHandle1xx() const STUB_RETVAL(false)
#if USE_ADAPTATION
Adaptation::History::Pointer HttpRequest::adaptLogHistory() const STUB_RETVAL(Adaptation::History::Pointer())
Adaptation::History::Pointer HttpRequest::adaptHistory(bool) const STUB_RETVAL(Adaptation::History::Pointer())
void HttpRequest::adaptHistoryImport(const HttpRequest &) STUB
#endif
#if ICAP_CLIENT
Adaptation::Icap::History::Pointer HttpRequest::icapHistory() const STUB_RETVAL(Adaptation::Icap::History::Pointer())
#endif
void HttpRequest::recordLookup(const Dns::LookupDetails &) STUB
void HttpRequest::detailError(err_type, int) STUB
void HttpRequest::clearError() STUB
void HttpRequest::clean() STUB
void HttpRequest::init() STUB
static const SBuf nilSBuf;
const SBuf &HttpRequest::effectiveRequestUri() const STUB_RETVAL(nilSBuf)
bool HttpRequest::multipartRangeRequest() const STUB_RETVAL(false)
bool HttpRequest::parseFirstLine(const char *, const char *) STUB_RETVAL(false)
bool HttpRequest::expectingBody(const HttpRequestMethod &, int64_t &) const STUB_RETVAL(false)
bool HttpRequest::bodyNibbled() const STUB_RETVAL(false)
int HttpRequest::prefixLen() const STUB_RETVAL(0)
void HttpRequest::swapOut(StoreEntry *) STUB
void HttpRequest::pack(Packable *) const STUB
void HttpRequest::httpRequestPack(void *, Packable *) STUB
HttpRequest * HttpRequest::FromUrl(const SBuf &, const MasterXaction::Pointer &, const HttpRequestMethod &) STUB_RETVAL(nullptr)
HttpRequest * HttpRequest::FromUrlXXX(const char *, const MasterXaction::Pointer &, const HttpRequestMethod &) STUB_RETVAL(nullptr)
ConnStateData *HttpRequest::pinnedConnection() STUB_RETVAL(NULL)
const SBuf HttpRequest::storeId() STUB_RETVAL(SBuf("."))
void HttpRequest::ignoreRange(const char *) STUB
int64_t HttpRequest::getRangeOffsetLimit() STUB_RETVAL(0)
void HttpRequest::packFirstLineInto(Packable *, bool) const STUB
bool HttpRequest::sanityCheckStartLine(const char *, const size_t, Http::StatusCode *) STUB_RETVAL(false)
void HttpRequest::hdrCacheInit() STUB
bool HttpRequest::inheritProperties(const HttpMsg *) STUB_RETVAL(false)

