#include "squid.h"
#include "client_side.h"

#define STUB_API "client_side.cc"
#include "tests/STUB.h"

ClientSocketContext::ClientSocketContext() STUB
ClientSocketContext::~ClientSocketContext() STUB
bool ClientSocketContext::startOfOutput() const STUB_RETVAL(false)
void ClientSocketContext::writeComplete(const Comm::ConnectionPointer &conn, char *bufnotused, size_t size, comm_err_t errflag) STUB
void ClientSocketContext::keepaliveNextRequest() STUB
void ClientSocketContext::pullData() STUB
int64_t ClientSocketContext::getNextRangeOffset() const STUB_RETVAL(0)
bool ClientSocketContext::canPackMoreRanges() const STUB_RETVAL(false)
clientStream_status_t ClientSocketContext::socketState() STUB_RETVAL(STREAM_NONE)
void ClientSocketContext::sendBody(HttpReply * rep, StoreIOBuffer bodyData) STUB
void ClientSocketContext::sendStartOfMessage(HttpReply * rep, StoreIOBuffer bodyData) STUB
size_t ClientSocketContext::lengthToSend(Range<int64_t> const &available) STUB_RETVAL(0)
void ClientSocketContext::noteSentBodyBytes(size_t) STUB
void ClientSocketContext::buildRangeHeader(HttpReply * rep) STUB
clientStreamNode * ClientSocketContext::getTail() const STUB_RETVAL(NULL)
clientStreamNode * ClientSocketContext::getClientReplyContext() const STUB_RETVAL(NULL)
void ClientSocketContext::connIsFinished() STUB
void ClientSocketContext::removeFromConnectionList(ConnStateData * conn) STUB
void ClientSocketContext::deferRecipientForLater(clientStreamNode * node, HttpReply * rep, StoreIOBuffer receivedData) STUB
bool ClientSocketContext::multipartRangeRequest() const STUB_RETVAL(false)
void ClientSocketContext::registerWithConn() STUB
void ClientSocketContext::noteIoError(const int xerrno) STUB
void ClientSocketContext::writeControlMsg(HttpControlMsg &msg) STUB

void ConnStateData::readSomeData() STUB
int ConnStateData::getAvailableBufferLength() const STUB_RETVAL(0)
bool ConnStateData::areAllContextsForThisConnection() const STUB_RETVAL(false)
void ConnStateData::freeAllContexts() STUB
void ConnStateData::notifyAllContexts(const int xerrno) STUB
bool ConnStateData::clientParseRequests() STUB_RETVAL(false)
void ConnStateData::readNextRequest() STUB
bool ConnStateData::maybeMakeSpaceAvailable() STUB_RETVAL(false)
void ConnStateData::addContextToQueue(ClientSocketContext * context) STUB
int ConnStateData::getConcurrentRequestCount() const STUB_RETVAL(0)
bool ConnStateData::isOpen() const STUB_RETVAL(false)
void ConnStateData::checkHeaderLimits() STUB
void ConnStateData::sendControlMsg(HttpControlMsg msg) STUB
char *ConnStateData::In::addressToReadInto() const STUB_RETVAL(NULL)
int64_t ConnStateData::mayNeedToReadMoreBody() const STUB_RETVAL(0)
#if USE_AUTH
void ConnStateData::setAuth(const Auth::UserRequest::Pointer &aur, const char *cause) STUB
#endif
bool ConnStateData::transparent() const STUB_RETVAL(false)
bool ConnStateData::reading() const STUB_RETVAL(false)
void ConnStateData::stopReading() STUB
void ConnStateData::stopReceiving(const char *error) STUB
void ConnStateData::stopSending(const char *error) STUB
void ConnStateData::expectNoForwarding() STUB
void ConnStateData::noteMoreBodySpaceAvailable(BodyPipe::Pointer) STUB
void ConnStateData::noteBodyConsumerAborted(BodyPipe::Pointer) STUB
bool ConnStateData::handleReadData(char *buf, size_t size) STUB_RETVAL(false)
bool ConnStateData::handleRequestBodyData() STUB_RETVAL(false)
void ConnStateData::pinConnection(const Comm::ConnectionPointer &pinServerConn, HttpRequest *request, CachePeer *peer, bool auth) STUB
void ConnStateData::unpinConnection() STUB
const Comm::ConnectionPointer ConnStateData::validatePinnedConnection(HttpRequest *request, const CachePeer *peer) STUB_RETVAL(NULL)
void ConnStateData::clientPinnedConnectionClosed(const CommCloseCbParams &io) STUB
void ConnStateData::clientReadRequest(const CommIoCbParams &io) STUB
void ConnStateData::connStateClosed(const CommCloseCbParams &io) STUB
void ConnStateData::requestTimeout(const CommTimeoutCbParams &params) STUB
void ConnStateData::swanSong() STUB
void ConnStateData::quitAfterError(HttpRequest *request) STUB
#if USE_SSL
void ConnStateData::httpsPeeked(Comm::ConnectionPointer serverConnection) STUB
void ConnStateData::getSslContextStart() STUB
void ConnStateData::getSslContextDone(SSL_CTX * sslContext, bool isNew) STUB
void ConnStateData::sslCrtdHandleReplyWrapper(void *data, const HelperReply &reply) STUB
void ConnStateData::sslCrtdHandleReply(const HelperReply &reply) STUB
void ConnStateData::switchToHttps(HttpRequest *request, Ssl::BumpMode bumpServerMode) STUB
void ConnStateData::buildSslCertGenerationParams(Ssl::CertificateProperties &certProperties) STUB
bool ConnStateData::serveDelayedError(ClientSocketContext *context) STUB_RETVAL(false)
#endif

void setLogUri(ClientHttpRequest * http, char const *uri, bool cleanUrl) STUB
const char *findTrailingHTTPVersion(const char *uriAndHTTPVersion, const char *end) STUB_RETVAL(NULL)
int varyEvaluateMatch(StoreEntry * entry, HttpRequest * req) STUB_RETVAL(0)
void clientOpenListenSockets(void) STUB
void clientHttpConnectionsClose(void) STUB
void httpRequestFree(void *) STUB
