/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "client_side.h"
#include "http/StreamContext.h"

#define STUB_API "client_side.cc"
#include "tests/STUB.h"

//Http::StreamContext::Http::StreamContext(const ConnectionPointer&, ClientHttpRequest*) STUB
//Http::StreamContext::~Http::StreamContext() STUB
bool Http::StreamContext::startOfOutput() const STUB_RETVAL(false)
void Http::StreamContext::writeComplete(size_t size) STUB
void Http::StreamContext::pullData() STUB
int64_t Http::StreamContext::getNextRangeOffset() const STUB_RETVAL(0)
bool Http::StreamContext::canPackMoreRanges() const STUB_RETVAL(false)
clientStream_status_t Http::StreamContext::socketState() STUB_RETVAL(STREAM_NONE)
void Http::StreamContext::sendBody(HttpReply * rep, StoreIOBuffer bodyData) STUB
void Http::StreamContext::sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData) STUB
size_t Http::StreamContext::lengthToSend(Range<int64_t> const &available) STUB_RETVAL(0)
void Http::StreamContext::noteSentBodyBytes(size_t) STUB
void Http::StreamContext::buildRangeHeader(HttpReply * rep) STUB
clientStreamNode * Http::StreamContext::getTail() const STUB_RETVAL(NULL)
clientStreamNode * Http::StreamContext::getClientReplyContext() const STUB_RETVAL(NULL)
void Http::StreamContext::finished() STUB
void Http::StreamContext::deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer receivedData) STUB
bool Http::StreamContext::multipartRangeRequest() const STUB_RETVAL(false)
void Http::StreamContext::registerWithConn() STUB
void Http::StreamContext::noteIoError(const int xerrno) STUB

bool ConnStateData::clientParseRequests() STUB_RETVAL(false)
void ConnStateData::readNextRequest() STUB
bool ConnStateData::isOpen() const STUB_RETVAL(false)
void ConnStateData::kick() STUB
void ConnStateData::sendControlMsg(HttpControlMsg msg) STUB
int64_t ConnStateData::mayNeedToReadMoreBody() const STUB_RETVAL(0)
#if USE_AUTH
void ConnStateData::setAuth(const Auth::UserRequest::Pointer &aur, const char *cause) STUB
#endif
bool ConnStateData::transparent() const STUB_RETVAL(false)
void ConnStateData::stopReceiving(const char *error) STUB
void ConnStateData::stopSending(const char *error) STUB
void ConnStateData::expectNoForwarding() STUB
void ConnStateData::noteMoreBodySpaceAvailable(BodyPipe::Pointer) STUB
void ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer) STUB
bool ConnStateData::handleReadData() STUB_RETVAL(false)
bool ConnStateData::handleRequestBodyData() STUB_RETVAL(false)
void ConnStateData::pinConnection(const Comm::ConnectionPointer &pinServerConn, HttpRequest *request, CachePeer *peer, bool auth, bool monitor) STUB
void ConnStateData::unpinConnection(const bool andClose) STUB
const Comm::ConnectionPointer ConnStateData::validatePinnedConnection(HttpRequest *request, const CachePeer *peer) STUB_RETVAL(NULL)
void ConnStateData::clientPinnedConnectionClosed(const CommCloseCbParams &io) STUB
void ConnStateData::connStateClosed(const CommCloseCbParams &io) STUB
void ConnStateData::requestTimeout(const CommTimeoutCbParams &params) STUB
void ConnStateData::swanSong() STUB
void ConnStateData::quitAfterError(HttpRequest *request) STUB
#if USE_OPENSSL
void ConnStateData::httpsPeeked(Comm::ConnectionPointer serverConnection) STUB
void ConnStateData::getSslContextStart() STUB
void ConnStateData::getSslContextDone(Security::ContextPtr, bool) STUB
void ConnStateData::sslCrtdHandleReplyWrapper(void *data, const Helper::Reply &reply) STUB
void ConnStateData::sslCrtdHandleReply(const Helper::Reply &reply) STUB
void ConnStateData::switchToHttps(HttpRequest *request, Ssl::BumpMode bumpServerMode) STUB
void ConnStateData::buildSslCertGenerationParams(Ssl::CertificateProperties &certProperties) STUB
bool ConnStateData::serveDelayedError(Http::StreamContext *context) STUB_RETVAL(false)
#endif

void setLogUri(ClientHttpRequest * http, char const *uri, bool cleanUrl) STUB
const char *findTrailingHTTPVersion(const char *uriAndHTTPVersion, const char *end) STUB_RETVAL(NULL)
int varyEvaluateMatch(StoreEntry * entry, HttpRequest * req) STUB_RETVAL(0)
void clientOpenListenSockets(void) STUB
void clientHttpConnectionsClose(void) STUB
void httpRequestFree(void *) STUB

