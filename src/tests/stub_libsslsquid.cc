/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "fatal.h"
#include "sbuf/Algorithms.h"
#include "sbuf/SBuf.h"

/* Stub File for the ssl/libsslsquid.la convenience library */

#define STUB_API "ssl/libsslsquid.la"
#include "tests/STUB.h"

#include "ssl/Config.h"
Ssl::Config::Config():
#if USE_SSL_CRTD
    ssl_crtd(nullptr),
#endif
    ssl_crt_validator(nullptr)
{
    ssl_crt_validator_Children.concurrency = 1;
    STUB_NOP
}
Ssl::Config::~Config() STUB_NOP
Ssl::Config Ssl::TheConfig;

#include "ssl/context_storage.h"
namespace  Ssl
{
//CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &) STUB
CertificateStorageAction::Pointer CertificateStorageAction::Create(const Mgr::Command::Pointer &) STUB_RETSTATREF(CertificateStorageAction::Pointer)
void CertificateStorageAction::dump(StoreEntry *) STUB
GlobalContextStorage::GlobalContextStorage() {STUB_NOP}
GlobalContextStorage::~GlobalContextStorage() {STUB_NOP}
void GlobalContextStorage::addLocalStorage(Ip::Address const &, size_t) STUB
LocalContextStorage *GlobalContextStorage::getLocalStorage(Ip::Address const &)
{ fatal(STUB_API " required"); static LocalContextStorage v(0,0); return &v; }
void GlobalContextStorage::reconfigureStart() STUB
//void lobalContextStorage::reconfigureFinish();
GlobalContextStorage TheGlobalContextStorage;
} //namespace Ssl

#include "ssl/ErrorDetail.h"
namespace Ssl
{
bool ParseErrorString(const char *, Security::Errors &) STUB_RETVAL(false)
Security::ErrorCode GetErrorCode(const char *) STUB_RETVAL(0)
const char *GetErrorName(Security::ErrorCode, const bool) STUB_RETVAL(nullptr)
const char *GetErrorDescr(Security::ErrorCode) STUB_RETVAL(nullptr)
bool ErrorIsOptional(const char *) STUB_RETVAL(false)
//const char *getErrorName(Security::ErrorCode value) STUB_RETVAL(nullptr)
Ssl::ErrorDetail::ErrorDetail(Security::ErrorCode, X509 *, X509 *, const char *) STUB
Ssl::ErrorDetail::ErrorDetail(ErrorDetail const &) STUB
const String &ErrorDetail::toString() const STUB_RETSTATREF(String)
const char *ErrorDetail::err_code() const STUB_RETVAL(nullptr)
}//namespace Ssl

#include "ssl/ErrorDetailManager.h"
namespace Ssl
{
bool ErrorDetailsList::getRecord(Security::ErrorCode, ErrorDetailEntry &) STUB_RETVAL(false)
const char *ErrorDetailsList::getErrorDescr(Security::ErrorCode) STUB_RETVAL(nullptr)
const char *ErrorDetailsList::getErrorDetail(Security::ErrorCode) STUB_RETVAL(nullptr)
//ErrorDetailsManager::ErrorDetailsManager() {STUB}
ErrorDetailsManager &ErrorDetailsManager::GetInstance() STUB_RETVAL(*ErrorDetailsManager::TheDetailsManager)
void ErrorDetailsManager::Shutdown() STUB
bool ErrorDetailsManager::getErrorDetail(Security::ErrorCode, const HttpRequest::Pointer &, ErrorDetailEntry &) STUB_RETVAL(false)
const char *ErrorDetailsManager::getDefaultErrorDescr(Security::ErrorCode) STUB_RETVAL(nullptr)
const char *ErrorDetailsManager::getDefaultErrorDetail(Security::ErrorCode) STUB_RETVAL(nullptr)
ErrorDetailsManager *ErrorDetailsManager::TheDetailsManager = nullptr;
void errorDetailInitialize() STUB
void errorDetailClean() STUB
} //namespace Ssl

#include "ssl/helper.h"
namespace Ssl
{
void Helper::Init() STUB
void Helper::Shutdown() STUB
void Helper::Submit(CrtdMessage const &, HLPCB *, void *) STUB
} // namespace Ssl

#include "ssl/PeekingPeerConnector.h"
CBDATA_NAMESPACED_CLASS_INIT(Ssl, PeekingPeerConnector);
namespace Ssl
{
bool PeekingPeerConnector::initialize(Security::SessionPointer &) STUB_RETVAL(false)
Security::ContextPointer PeekingPeerConnector::getTlsContext() STUB_RETVAL(Security::ContextPointer())
void PeekingPeerConnector::noteWantWrite() STUB
void PeekingPeerConnector::noteNegotiationError(const int, const int, const int) STUB
void PeekingPeerConnector::noteNegotiationDone(ErrorState *) STUB
void PeekingPeerConnector::handleServerCertificate() STUB
void PeekingPeerConnector::checkForPeekAndSplice() STUB
void PeekingPeerConnector::checkForPeekAndSpliceDone(Acl::Answer) STUB
void PeekingPeerConnector::checkForPeekAndSpliceMatched(const Ssl::BumpMode) STUB
Ssl::BumpMode PeekingPeerConnector::checkForPeekAndSpliceGuess() const STUB_RETVAL(Ssl::bumpNone)
void PeekingPeerConnector::serverCertificateVerified() STUB
void PeekingPeerConnector::cbCheckForPeekAndSpliceDone(Acl::Answer, void *) STUB
} // namespace Ssl

#include "ssl/ServerBump.h"
CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerBump);
namespace Ssl
{
ServerBump::ServerBump(ClientHttpRequest *, StoreEntry *, Ssl::BumpMode) {STUB}
ServerBump::~ServerBump() {STUB}
void ServerBump::attachServerSession(const Security::SessionPointer &) STUB
const Security::CertErrors *ServerBump::sslErrors() const STUB_RETVAL(nullptr)
} // namespace Ssl

#include "ssl/support.h"
namespace Ssl
{
bool ParseErrorString(const char *, Security::Errors &) STUB_RETVAL(false)
int AskPasswordCb(char *, int, int, void *) STUB_RETVAL(0)
void Initialize() STUB
bool InitServerContext(Security::ContextPointer &, AnyP::PortCfg &) STUB_RETVAL(false)
bool InitClientContext(Security::ContextPointer &, Security::PeerOptions &, long) STUB_RETVAL(false)
void SetupVerifyCallback(Security::ContextPointer &) STUB
void MaybeSetupRsaCallback(Security::ContextPointer &) STUB
} // namespace Ssl
const char *sslGetUserEmail(SSL *) STUB_RETVAL(nullptr)
const char *sslGetUserAttribute(SSL *, const char *) STUB_RETVAL(nullptr)
const char *sslGetCAAttribute(SSL *, const char *) STUB_RETVAL(nullptr)
SBuf sslGetUserCertificatePEM(SSL *) STUB_RETVAL(SBuf())
SBuf sslGetUserCertificateChainPEM(SSL *) STUB_RETVAL(SBuf())
namespace Ssl
{
const char *GetX509UserAttribute(X509 *, const char *) STUB_RETVAL(nullptr)
const char *GetX509CAAttribute(X509 *, const char *) STUB_RETVAL(nullptr)
const char *GetX509Fingerprint(X509 *, const char *) STUB_RETVAL(nullptr)
Security::DigestAlgorithm DefaultSignHash = UnknownDigestAlgorithm;
std::vector<const char *> BumpModeStr = {""};
bool loadCerts(const char *, Ssl::CertsIndexedList &) STUB_RETVAL(false)
bool loadSquidUntrusted(const char *) STUB_RETVAL(false)
void unloadSquidUntrusted() STUB
void SSL_add_untrusted_cert(SSL *, X509 *) STUB
const char *uriOfIssuerIfMissing(X509 *, Security::CertList const &, const Security::ContextPointer &) STUB_RETVAL(nullptr)
void missingChainCertificatesUrls(std::queue<SBuf> &, Security::CertList const &, const Security::ContextPointer &) STUB
bool generateUntrustedCert(Security::CertPointer &, Security::PrivateKeyPointer &, Security::CertPointer const &, Security::PrivateKeyPointer const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContext(Security::CertificateProperties const &, Security::ServerOptions &, bool) STUB_RETVAL(Security::ContextPointer())
bool verifySslCertificate(Security::ContextPointer &, Security::CertificateProperties const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContextUsingPkeyAndCertFromMemory(const char *, Security::ServerOptions &, bool) STUB_RETVAL(Security::ContextPointer())
Security::ContextPointer createSSLContext(Security::CertPointer &, Security::PrivateKeyPointer &, Security::ServerOptions &) STUB_RETVAL(Security::ContextPointer())
void chainCertificatesToSSLContext(Security::ContextPointer &, Security::ServerOptions &) STUB
void configureUnconfiguredSslContext(Security::ContextPointer &, Security::CertSignAlgorithm, AnyP::PortCfg &) STUB
bool configureSSL(SSL *, Security::CertificateProperties const &, AnyP::PortCfg &) STUB_RETVAL(false)
bool configureSSLUsingPkeyAndCertFromMemory(SSL *, const char *, AnyP::PortCfg &) STUB_RETVAL(false)
void useSquidUntrusted(SSL_CTX *) STUB
int matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data)) STUB_RETVAL(0)
bool checkX509ServerValidity(X509 *cert, const char *server) STUB_RETVAL(false)
int asn1timeToString(ASN1_TIME *tm, char *buf, int len) STUB_RETVAL(0)
void setClientSNI(SSL *ssl, const char *fqdn) STUB
SBuf GetX509PEM(X509 *) STUB_RETVAL(SBuf())
void InRamCertificateDbKey(const Security::CertificateProperties &, SBuf &) STUB
BIO *BIO_new_SBuf(SBuf *) STUB_RETVAL(nullptr)
} //namespace Ssl

#endif

