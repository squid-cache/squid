/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "SquidConfig.h"

#define STUB_API "http/libhttp.la"
#include "tests/STUB.h"

#include "http/ContentLengthInterpreter.h"
namespace Http
{
// XXX: use C++11 initialization for this class
Http::ContentLengthInterpreter::ContentLengthInterpreter():
    value(-1),
    headerWideProblem(nullptr),
    debugLevel(Config.onoff.relaxed_header_parser <= 0 ? DBG_IMPORTANT : 2),
    sawBad(false),
    needsSanitizing(false),
    sawGood(false),
    prohibitedAndIgnored_(nullptr)
{
}
bool ContentLengthInterpreter::checkField(const String &) STUB_RETVAL(false)
bool ContentLengthInterpreter::goodSuffix(const char *, const char * const) const STUB_RETVAL(false)
bool ContentLengthInterpreter::checkValue(const char *, const int) STUB_RETVAL(false)
bool ContentLengthInterpreter::checkList(const String &) STUB_RETVAL(false)
}

#include "http/Message.h"
namespace Http
{
Message::Message(http_hdr_owner_type) {STUB}
Message::~Message() {STUB}
void Message::packInto(Packable *, bool) const STUB
void Message::setContentLength(int64_t) STUB
bool Message::persistent() const STUB_RETVAL(false)
void Message::putCc(const HttpHdrCc *) STUB
bool Message::parse(const char *, const size_t, bool, Http::StatusCode *) STUB_RETVAL(false)
bool Message::parseCharBuf(const char *, ssize_t) STUB_RETVAL(false)
int Message::httpMsgParseStep(const char *, int, int) STUB_RETVAL(-1)
int Message::httpMsgParseError() STUB_RETVAL(0)
void Message::firstLineBuf(MemBuf&) STUB
void Message::hdrCacheInit() STUB
bool Message::parseHeader(Http1::Parser &, Http::ContentLengthInterpreter &) STUB_RETVAL(false)
}

#include "http/MethodType.h"
namespace Http
{
const SBuf MethodType_sb[1] = {SBuf()};
}

#include "http/RegisteredHeaders.h"
namespace Http
{
HeaderTableRecord::HeaderTableRecord(const char *) {STUB_NOP}
HeaderTableRecord::HeaderTableRecord(const char *, Http::HdrType, Http::HdrFieldType, int) {STUB}
HeaderLookupTable_t::HeaderLookupTable_t() {STUB_NOP}
const HeaderTableRecord& HeaderLookupTable_t::lookup(const char *, const std::size_t) const STUB_RETVAL(BadHdr)
const HeaderLookupTable_t HeaderLookupTable;
}
std::ostream &Http::operator <<(std::ostream &os, HdrType) STUB_RETVAL(os)

#include "http/RequestMethod.h"
HttpRequestMethod::HttpRequestMethod(const SBuf &) {STUB}
void HttpRequestMethod::HttpRequestMethodXXX(char const *) STUB
const SBuf &HttpRequestMethod::image() const STUB_RETVAL(theImage)
bool HttpRequestMethod::isHttpSafe() const STUB_RETVAL(false)
bool HttpRequestMethod::isIdempotent() const STUB_RETVAL(false)
bool HttpRequestMethod::respMaybeCacheable() const STUB_RETVAL(false)
bool HttpRequestMethod::shouldInvalidate() const STUB_RETVAL(false)
bool HttpRequestMethod::purgesOthers() const STUB_RETVAL(false)

#include "http/StatusCode.h"
namespace Http
{
const char *StatusCodeString(const Http::StatusCode) STUB_RETVAL(nullptr)
}

#include "http/StatusLine.h"
namespace Http
{
void StatusLine::init() STUB
void StatusLine::clean() STUB
void StatusLine::set(const AnyP::ProtocolVersion &, Http::StatusCode, const char *) STUB
const char *StatusLine::reason() const STUB_RETVAL(nullptr)
void StatusLine::packInto(Packable *) const STUB
bool StatusLine::parse(const String &, const char *, const char *) STUB_RETVAL(false)
}

#include "http/Stream.h"
namespace Http
{
Stream::Stream(const Comm::ConnectionPointer &, ClientHttpRequest *) {STUB}
Stream::~Stream() {STUB}
void Stream::registerWithConn() STUB
bool Stream::startOfOutput() const STUB
void Stream::writeComplete(size_t) STUB
void Stream::pullData() STUB
bool Stream::multipartRangeRequest() const STUB_RETVAL(false)
int64_t Stream::getNextRangeOffset() const STUB_RETVAL(-1)
bool Stream::canPackMoreRanges() const STUB_RETVAL(false)
size_t Stream::lengthToSend(Range<int64_t> const &) const STUB_RETVAL(0)
clientStream_status_t Stream::socketState() STUB_RETVAL(STREAM_NONE)
void Stream::sendStartOfMessage(HttpReply *, StoreIOBuffer) STUB
void Stream::sendBody(StoreIOBuffer) STUB
void Stream::noteSentBodyBytes(size_t) STUB
void Stream::buildRangeHeader(HttpReply *) STUB
clientStreamNode *Stream::getTail() const STUB_RETVAL(nullptr)
clientStreamNode *Stream::getClientReplyContext() const STUB_RETVAL(nullptr)
ConnStateData *Stream::getConn() const STUB_RETVAL(nullptr)
void Stream::noteIoError(const Error &, const LogTagsErrors &) STUB
void Stream::finished() STUB
void Stream::initiateClose(const char *) STUB
void Stream::deferRecipientForLater(clientStreamNode *, HttpReply *, StoreIOBuffer) STUB
}

