/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ETag.h"
#include "TimeOrTag.h"

#define STUB_API "HttpHeader.cc"
#include "STUB.h"

#include "HttpHeader.h"
HttpHeaderEntry::HttpHeaderEntry(Http::HdrType, const SBuf &, const char *) {STUB}
HttpHeaderEntry::~HttpHeaderEntry() {STUB}
HttpHeaderEntry *HttpHeaderEntry::parse(const char *, const char *) STUB_RETVAL(nullptr)
HttpHeaderEntry *HttpHeaderEntry::clone() const STUB_RETVAL(nullptr)
void HttpHeaderEntry::packInto(Packable *) const STUB
int HttpHeaderEntry::getInt() const STUB_RETVAL(0)
int64_t HttpHeaderEntry::getInt64() const STUB_RETVAL(0)
HttpHeader::HttpHeader() {STUB}
HttpHeader::HttpHeader(const http_hdr_owner_type) {STUB}
HttpHeader::HttpHeader(const HttpHeader &) {STUB}
HttpHeader::~HttpHeader() {STUB}
HttpHeader &HttpHeader::operator =(const HttpHeader &other) STUB_RETVAL(*this)
void HttpHeader::clean() STUB
void HttpHeader::append(const HttpHeader *) STUB
bool HttpHeader::update(HttpHeader const *) STUB_RETVAL(false)
void HttpHeader::compact() STUB
int HttpHeader::parse(const char *, size_t, Http::ContentLengthInterpreter &) STUB_RETVAL(-1)
int HttpHeader::parse(const char *, size_t, bool, size_t &, Http::ContentLengthInterpreter &) STUB_RETVAL(-1)
void HttpHeader::packInto(Packable *, bool) const STUB
HttpHeaderEntry *HttpHeader::getEntry(HttpHeaderPos *) const STUB_RETVAL(nullptr)
HttpHeaderEntry *HttpHeader::findEntry(Http::HdrType) const STUB_RETVAL(nullptr)
int HttpHeader::delByName(const SBuf &) STUB_RETVAL(0)
int HttpHeader::delById(Http::HdrType) STUB_RETVAL(0)
void HttpHeader::delAt(HttpHeaderPos, int &) STUB
void HttpHeader::refreshMask() STUB
void HttpHeader::addEntry(HttpHeaderEntry *) STUB
void HttpHeader::insertEntry(HttpHeaderEntry *) STUB
String HttpHeader::getList(Http::HdrType) const STUB_RETVAL(String())
bool HttpHeader::getList(Http::HdrType, String *) const STUB_RETVAL(false)
String HttpHeader::getStrOrList(Http::HdrType) const STUB_RETVAL(String())
String HttpHeader::getByName(const SBuf &) const STUB_RETVAL(String())
String HttpHeader::getByName(const char *) const STUB_RETVAL(String())
String HttpHeader::getById(Http::HdrType) const STUB_RETVAL(String())
bool HttpHeader::getByIdIfPresent(Http::HdrType, String *) const STUB_RETVAL(false)
bool HttpHeader::hasNamed(const SBuf &, String *) const STUB_RETVAL(false)
bool HttpHeader::hasNamed(const char *, unsigned int, String *) const STUB_RETVAL(false)
SBuf HttpHeader::getByNameListMember(const char *, const char *, const char) const STUB_RETVAL(SBuf())
SBuf HttpHeader::getListMember(Http::HdrType, const char *, const char) const STUB_RETVAL(SBuf())
int HttpHeader::has(Http::HdrType) const STUB_RETVAL(0)
void HttpHeader::addVia(const AnyP::ProtocolVersion &, const HttpHeader *) STUB
void HttpHeader::putInt(Http::HdrType, int) STUB
void HttpHeader::putInt64(Http::HdrType, int64_t ) STUB
void HttpHeader::putTime(Http::HdrType, time_t) STUB
void HttpHeader::putStr(Http::HdrType, const char *) STUB
void HttpHeader::putAuth(const char *, const char *) STUB
void HttpHeader::putCc(const HttpHdrCc *) STUB
void HttpHeader::putContRange(const HttpHdrContRange *) STUB
void HttpHeader::putRange(const HttpHdrRange *) STUB
void HttpHeader::putSc(HttpHdrSc *) STUB
void HttpHeader::putWarning(const int, const char *const) STUB
void HttpHeader::putExt(const char *, const char *) STUB
int HttpHeader::getInt(Http::HdrType) const STUB_RETVAL(0)
int64_t HttpHeader::getInt64(Http::HdrType) const STUB_RETVAL(0)
time_t HttpHeader::getTime(Http::HdrType) const STUB_RETVAL(0)
const char *HttpHeader::getStr(Http::HdrType) const STUB_RETVAL(nullptr)
const char *HttpHeader::getLastStr(Http::HdrType) const STUB_RETVAL(nullptr)
HttpHdrCc *HttpHeader::getCc() const STUB_RETVAL(nullptr)
HttpHdrRange *HttpHeader::getRange() const STUB_RETVAL(nullptr)
HttpHdrSc *HttpHeader::getSc() const STUB_RETVAL(nullptr)
HttpHdrContRange *HttpHeader::getContRange() const STUB_RETVAL(nullptr)
SBuf HttpHeader::getAuthToken(Http::HdrType, const char *) const STUB_RETVAL(SBuf())
ETag HttpHeader::getETag(Http::HdrType) const STUB_RETVAL(ETag())
TimeOrTag HttpHeader::getTimeOrTag(Http::HdrType) const STUB_RETVAL(TimeOrTag())
int HttpHeader::hasListMember(Http::HdrType, const char *, const char) const STUB_RETVAL(0)
int HttpHeader::hasByNameListMember(const char *, const char *, const char) const STUB_RETVAL(0)
void HttpHeader::removeHopByHopEntries() STUB
void HttpHeader::removeConnectionHeaderEntries() STUB
bool HttpHeader::Isolate(const char **, size_t, const char **, const char **) STUB_RETVAL(false)
bool HttpHeader::needUpdate(const HttpHeader *fresh) const STUB_RETVAL(false)
bool HttpHeader::skipUpdateHeader(const Http::HdrType) const STUB_RETVAL(false)
void HttpHeader::updateWarnings() STUB
int httpHeaderParseQuotedString(const char *, const int, String *) STUB_RETVAL(-1)
SBuf httpHeaderQuoteString(const char *) STUB_RETVAL(SBuf())
void httpHeaderCalcMask(HttpHeaderMask *, Http::HdrType [], size_t) STUB
void httpHeaderInitModule() STUB

