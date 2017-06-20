/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
bool BlindPeerConnector::initialize(Security::SessionPointer &) STUB_RETVAL(false)
Security::ContextPointer BlindPeerConnector::getTlsContext() STUB_RETVAL(Security::ContextPointer())
void BlindPeerConnector::noteNegotiationDone(ErrorState *) STUB
}

#include "security/EncryptorAnswer.h"
Security::EncryptorAnswer::~EncryptorAnswer() {}
std::ostream &Security::operator <<(std::ostream &os, const Security::EncryptorAnswer &) STUB_RETVAL(os)

#include "security/Handshake.h"
Security::HandshakeParser::HandshakeParser() STUB
bool Security::HandshakeParser::parseHello(const SBuf &) STUB_RETVAL(false)

#include "security/NegotiationHistory.h"
Security::NegotiationHistory::NegotiationHistory() STUB
void Security::NegotiationHistory::retrieveNegotiatedInfo(const Security::SessionPointer &) STUB
void Security::NegotiationHistory::retrieveParsedInfo(Security::TlsDetails::Pointer const &) STUB
const char *Security::NegotiationHistory::cipherName() const STUB
const char *Security::NegotiationHistory::printTlsVersion(AnyP::ProtocolVersion const &v) const STUB

#include "security/PeerConnector.h"
CBDATA_NAMESPACED_CLASS_INIT(Security, PeerConnector);
namespace Security
{
PeerConnector::PeerConnector(const Comm::ConnectionPointer &, AsyncCall::Pointer &, const AccessLogEntryPointer &, const time_t) :
    AsyncJob("Security::PeerConnector") {STUB}
PeerConnector::~PeerConnector() {STUB}
void PeerConnector::start() STUB
bool PeerConnector::doneAll() const STUB_RETVAL(true)
void PeerConnector::swanSong() STUB
const char *PeerConnector::status() const STUB_RETVAL("")
void PeerConnector::commCloseHandler(const CommCloseCbParams &) STUB
void PeerConnector::connectionClosed(const char *) STUB
bool PeerConnector::prepareSocket() STUB_RETVAL(false)
void PeerConnector::setReadTimeout() STUB
bool PeerConnector::initialize(Security::SessionPointer &) STUB_RETVAL(false)
void PeerConnector::negotiate() STUB
bool PeerConnector::sslFinalized() STUB_RETVAL(false)
void PeerConnector::handleNegotiateError(const int) STUB
void PeerConnector::noteWantRead() STUB
void PeerConnector::noteWantWrite() STUB
void PeerConnector::noteNegotiationError(const int, const int, const int) STUB
//    virtual Security::ContextPointer getTlsContext() = 0;
void PeerConnector::bail(ErrorState *) STUB
void PeerConnector::callBack() STUB
void PeerConnector::recordNegotiationDetails() STUB
}

#include "security/PeerOptions.h"
Security::PeerOptions Security::ProxyOutgoingConfig;
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
void Security::PeerOptions::updateSessionOptions(Security::SessionPointer &) STUB
void Security::PeerOptions::dumpCfg(Packable*, char const*) const STUB
void Security::PeerOptions::parseOptions() STUB
void parse_securePeerOptions(Security::PeerOptions *) STUB

#include "security/ServerOptions.h"
//Security::ServerOptions::ServerOptions(const Security::ServerOptions &) STUB
void Security::ServerOptions::parse(const char *) STUB
void Security::ServerOptions::dumpCfg(Packable *, const char *) const STUB
Security::ContextPointer Security::ServerOptions::createBlankContext() const STUB_RETVAL(Security::ContextPointer())
bool Security::ServerOptions::createStaticServerContext(AnyP::PortCfg &) STUB_RETVAL(false)
void Security::ServerOptions::updateContextEecdh(Security::ContextPointer &) STUB

#include "security/Session.h"
namespace Security {
bool CreateClientSession(const Security::ContextPointer &, const Comm::ConnectionPointer &, const char *) STUB_RETVAL(false)
bool CreateServerSession(const Security::ContextPointer &, const Comm::ConnectionPointer &, const char *) STUB_RETVAL(false)
void SessionSendGoodbye(const Security::SessionPointer &) STUB
bool SessionIsResumed(const Security::SessionPointer &) STUB_RETVAL(false)
void MaybeGetSessionResumeData(const Security::SessionPointer &, Security::SessionStatePointer &) STUB
void SetSessionResumeData(const Security::SessionPointer &, const Security::SessionStatePointer &) STUB
#if USE_OPENSSL
void SetSessionCacheCallbacks(Security::ContextPointer &) STUB
Security::SessionPointer NewSessionObject(const Security::ContextPointer &) STUB_RETVAL(nullptr)
#endif
} // namespace Security

