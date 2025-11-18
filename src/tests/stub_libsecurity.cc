/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "comm/Connection.h"
#include "HttpRequest.h"

#define STUB_API "security/libsecurity.la"
#include "tests/STUB.h"

#include "security/BlindPeerConnector.h"
CBDATA_NAMESPACED_CLASS_INIT(Security, BlindPeerConnector);
namespace Security
{
BlindPeerConnector::BlindPeerConnector(HttpRequestPointer &, const Comm::ConnectionPointer & aServerConn,
                                       const AsyncCallback<EncryptorAnswer> & aCallback,
                                       const AccessLogEntryPointer &alp,
                                       time_t) :
    AsyncJob("Security::BlindPeerConnector"),
    Security::PeerConnector(aServerConn, aCallback, alp, 0)
{STUB_NOP}

bool BlindPeerConnector::initialize(Security::SessionPointer &) STUB_RETVAL(false)
FuturePeerContext *BlindPeerConnector::peerContext() const STUB_RETVAL(nullptr)
void BlindPeerConnector::noteNegotiationDone(ErrorState *) STUB
}

#include "security/EncryptorAnswer.h"
Security::EncryptorAnswer::~EncryptorAnswer() {}
std::ostream &Security::operator <<(std::ostream &os, const Security::EncryptorAnswer &) STUB_RETVAL(os)

#include "security/Certificate.h"
SBuf Security::SubjectName(Certificate &) STUB_RETVAL(SBuf())
SBuf Security::IssuerName(Certificate &) STUB_RETVAL(SBuf())
bool Security::IssuedBy(Certificate &, Certificate &) STUB_RETVAL(false)
std::ostream &operator <<(std::ostream &os, Security::Certificate &) STUB_RETVAL(os)

#include "security/Handshake.h"
Security::HandshakeParser::HandshakeParser(MessageSource) STUB
bool Security::HandshakeParser::parseHello(const SBuf &) STUB_RETVAL(false)

#include "security/Io.h"
Security::IoResult Security::Accept(Comm::Connection &) STUB_RETVAL(IoResult(IoResult::ioError))
Security::IoResult Security::Connect(Comm::Connection &) STUB_RETVAL(IoResult(IoResult::ioError))
void Security::IoResult::printGist(std::ostream &) const STUB
void Security::IoResult::printWithExtras(std::ostream &) const STUB
void Security::ForgetErrors() STUB
void Security::PrepForIo() STUB

#include "security/KeyData.h"
namespace Security
{
void KeyData::loadFromFiles(const AnyP::PortCfg &, const char *) STUB
}

#include "security/KeyLogger.h"
void Security::KeyLogger::maybeLog(const Connection &, const Acl::ChecklistFiller &) STUB

#include "security/ErrorDetail.h"
Security::ErrorDetail::ErrorDetail(ErrorCode, const CertPointer &, const CertPointer &, const char *) STUB
#if USE_OPENSSL
Security::ErrorDetail::ErrorDetail(ErrorCode, int, int) STUB
#elif HAVE_LIBGNUTLS
Security::ErrorDetail::ErrorDetail(ErrorCode, LibErrorCode, int) STUB
#endif
void Security::ErrorDetail::setPeerCertificate(const CertPointer &) STUB
SBuf Security::ErrorDetail::verbose(const HttpRequestPointer &) const STUB_RETVAL(SBuf())
SBuf Security::ErrorDetail::brief() const STUB_RETVAL(SBuf())
Security::ErrorCode Security::ErrorCodeFromName(const char *) STUB_RETVAL(0)
const char *Security::ErrorNameFromCode(ErrorCode, bool) STUB_RETVAL("")

#include "security/NegotiationHistory.h"
Security::NegotiationHistory::NegotiationHistory() STUB
void Security::NegotiationHistory::retrieveNegotiatedInfo(const Security::SessionPointer &) STUB
void Security::NegotiationHistory::retrieveParsedInfo(Security::TlsDetails::Pointer const &) STUB
const char *Security::NegotiationHistory::cipherName() const STUB
const char *Security::NegotiationHistory::printTlsVersion(AnyP::ProtocolVersion const &) const STUB

#include "security/PeerConnector.h"
class TlsNegotiationDetails: public RefCountable {};
namespace Security
{
PeerConnector::PeerConnector(const Comm::ConnectionPointer &, const AsyncCallback<EncryptorAnswer> &, const AccessLogEntryPointer &, const time_t):
    AsyncJob("Security::PeerConnector") {STUB}
PeerConnector::~PeerConnector() STUB
void PeerConnector::start() STUB
bool PeerConnector::doneAll() const STUB_RETVAL(true)
void PeerConnector::swanSong() STUB
const char *PeerConnector::status() const STUB_RETVAL("")
void PeerConnector::fillChecklist(ACLFilledChecklist &) const STUB
void PeerConnector::commCloseHandler(const CommCloseCbParams &) STUB
void PeerConnector::commTimeoutHandler(const CommTimeoutCbParams &) STUB
bool PeerConnector::initialize(Security::SessionPointer &) STUB_RETVAL(false)
void PeerConnector::negotiate() STUB
bool PeerConnector::sslFinalized() STUB_RETVAL(false)
void PeerConnector::handleNegotiationResult(const Security::IoResult &) STUB;
void PeerConnector::noteWantRead() STUB
void PeerConnector::noteWantWrite() STUB
void PeerConnector::noteNegotiationError(const Security::ErrorDetailPointer &) STUB
void PeerConnector::bail(ErrorState *) STUB
void PeerConnector::sendSuccess() STUB
void PeerConnector::callBack() STUB
void PeerConnector::disconnect() STUB
void PeerConnector::countFailingConnection() STUB
void PeerConnector::recordNegotiationDetails() STUB
EncryptorAnswer &PeerConnector::answer() STUB_RETREF(EncryptorAnswer)
}

#include "security/PeerOptions.h"
Security::PeerOptions &Security::ProxyOutgoingConfig() STUB_RETREF(Security::PeerOptions)

Security::PeerOptions::PeerOptions() {
#if USE_OPENSSL
    parsedOptions = 0;
#endif
    STUB_NOP
}
void Security::PeerOptions::parse(char const*) STUB
Security::ContextPointer Security::PeerOptions::createClientContext(bool) STUB_RETVAL(Security::ContextPointer())
void Security::PeerOptions::updateTlsVersionLimits() STUB
Security::ContextPointer Security::PeerOptions::createBlankContext() const STUB_RETVAL(Security::ContextPointer())
void Security::PeerOptions::updateContextCa(Security::ContextPointer &) STUB
void Security::PeerOptions::updateContextCrl(Security::ContextPointer &) STUB
void Security::PeerOptions::updateContextTrust(Security::ContextPointer &) STUB
void Security::PeerOptions::updateSessionOptions(Security::SessionPointer &) STUB
void Security::PeerOptions::dumpCfg(std::ostream &, char const*) const STUB
void Security::PeerOptions::parseOptions() STUB
void parse_securePeerOptions(Security::PeerOptions *) STUB

#include "security/ServerOptions.h"
//Security::ServerOptions::ServerOptions(const Security::ServerOptions &) STUB
Security::ServerOptions &Security::ServerOptions::operator=(Security::ServerOptions const&) STUB_RETVAL(*this);
void Security::ServerOptions::parse(const char *) STUB
void Security::ServerOptions::dumpCfg(std::ostream &, const char *) const STUB
Security::ContextPointer Security::ServerOptions::createBlankContext() const STUB_RETVAL(Security::ContextPointer())
void Security::ServerOptions::initServerContexts(AnyP::PortCfg&) STUB
bool Security::ServerOptions::createStaticServerContext(AnyP::PortCfg &) STUB_RETVAL(false)
void Security::ServerOptions::createSigningContexts(const AnyP::PortCfg &) STUB
bool Security::ServerOptions::updateContextConfig(Security::ContextPointer &) STUB_RETVAL(false)
void Security::ServerOptions::updateContextEecdh(Security::ContextPointer &) STUB
void Security::ServerOptions::updateContextClientCa(Security::ContextPointer &) STUB
void Security::ServerOptions::syncCaFiles() STUB
void Security::ServerOptions::updateContextSessionId(Security::ContextPointer &) STUB

#include "security/Session.h"
namespace Security {
bool CreateClientSession(FuturePeerContext &, const Comm::ConnectionPointer &, const char *) STUB_RETVAL(false)
bool CreateServerSession(const Security::ContextPointer &, const Comm::ConnectionPointer &, Security::PeerOptions &, const char *) STUB_RETVAL(false)
void SessionSendGoodbye(const Security::SessionPointer &) STUB
bool SessionIsResumed(const Security::SessionPointer &) STUB_RETVAL(false)
void MaybeGetSessionResumeData(const Security::SessionPointer &, Security::SessionStatePointer &) STUB
void SetSessionResumeData(const Security::SessionPointer &, const Security::SessionStatePointer &) STUB
#if USE_OPENSSL
void SetSessionCacheCallbacks(Security::ContextPointer &) STUB
Security::SessionPointer NewSessionObject(const Security::ContextPointer &) STUB_RETVAL(nullptr)
#endif
} // namespace Security

