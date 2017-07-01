/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "client_side_request.h"
#include "http/Stream.h"

#define STUB_API "client_side.cc"
#include "tests/STUB.h"

#include "client_side.h"
bool ConnStateData::clientParseRequests() STUB_RETVAL(false)
void ConnStateData::readNextRequest() STUB
bool ConnStateData::isOpen() const STUB_RETVAL(false)
void ConnStateData::kick() STUB
void ConnStateData::sendControlMsg(HttpControlMsg) STUB
int64_t ConnStateData::mayNeedToReadMoreBody() const STUB_RETVAL(0)
#if USE_AUTH
void ConnStateData::setAuth(const Auth::UserRequest::Pointer &, const char *) STUB
#endif
bool ConnStateData::transparent() const STUB_RETVAL(false)
void ConnStateData::stopReceiving(const char *) STUB
void ConnStateData::stopSending(const char *) STUB
void ConnStateData::expectNoForwarding() STUB
void ConnStateData::noteMoreBodySpaceAvailable(BodyPipe::Pointer) STUB
void ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer) STUB
bool ConnStateData::handleReadData() STUB_RETVAL(false)
bool ConnStateData::handleRequestBodyData() STUB_RETVAL(false)
void ConnStateData::pinBusyConnection(const Comm::ConnectionPointer &, const HttpRequest::Pointer &) STUB
void ConnStateData::notePinnedConnectionBecameIdle(PinnedIdleContext) STUB
void ConnStateData::unpinConnection(const bool) STUB
const Comm::ConnectionPointer ConnStateData::validatePinnedConnection(HttpRequest *, const CachePeer *) STUB_RETVAL(NULL)
void ConnStateData::clientPinnedConnectionClosed(const CommCloseCbParams &) STUB
void ConnStateData::connStateClosed(const CommCloseCbParams &) STUB
void ConnStateData::requestTimeout(const CommTimeoutCbParams &) STUB
void ConnStateData::swanSong() STUB
void ConnStateData::quitAfterError(HttpRequest *) STUB
#if USE_OPENSSL
void ConnStateData::httpsPeeked(PinnedIdleContext) STUB
void ConnStateData::getSslContextStart() STUB
void ConnStateData::getSslContextDone(Security::ContextPointer &, bool) STUB
void ConnStateData::sslCrtdHandleReplyWrapper(void *, const Helper::Reply &) STUB
void ConnStateData::sslCrtdHandleReply(const Helper::Reply &) STUB
void ConnStateData::switchToHttps(HttpRequest *, Ssl::BumpMode) STUB
void ConnStateData::buildSslCertGenerationParams(Ssl::CertificateProperties &) STUB
bool ConnStateData::serveDelayedError(Http::Stream *) STUB_RETVAL(false)
#endif

void setLogUri(ClientHttpRequest *, char const *, bool) STUB
const char *findTrailingHTTPVersion(const char *, const char *) STUB_RETVAL(NULL)
int varyEvaluateMatch(StoreEntry *, HttpRequest *) STUB_RETVAL(0)
void clientOpenListenSockets(void) STUB
void clientHttpConnectionsClose(void) STUB
void httpRequestFree(void *) STUB
void clientPackRangeHdr(const HttpReply *, const HttpHdrRangeSpec *, String, MemBuf *) STUB
void clientPackTermBound(String, MemBuf *) STUB

