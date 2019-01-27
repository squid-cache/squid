/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "fatal.h"
#include "sbuf/SBuf.h"

/* Stub File for the ssl/libsslsquid.la convenience library */

#define STUB_API "ssl/libsslsquid.la"
#include "tests/STUB.h"

#include "ssl/Config.h"
Ssl::Config::Config():
#if USE_SSL_CRTD
    ssl_crtd(NULL),
#endif
    ssl_crt_validator(NULL)
{
    ssl_crt_validator_Children.concurrency = 1;
    STUB_NOP
}
Ssl::Config::~Config() STUB_NOP
Ssl::Config Ssl::TheConfig;

#include "ssl/context_storage.h"
//Ssl::CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &cmd) STUB
Ssl::CertificateStorageAction::Pointer Ssl::CertificateStorageAction::Create(const Mgr::Command::Pointer &cmd) STUB_RETSTATREF(Ssl::CertificateStorageAction::Pointer)
void Ssl::CertificateStorageAction::dump(StoreEntry *sentry) STUB
void Ssl::GlobalContextStorage::addLocalStorage(Ip::Address const & address, size_t size_of_store) STUB
Ssl::LocalContextStorage *Ssl::GlobalContextStorage::getLocalStorage(Ip::Address const & address)
{ fatal(STUB_API " required"); static Ssl::LocalContextStorage v(0,0); return &v; }
void Ssl::GlobalContextStorage::reconfigureStart() STUB
//Ssl::GlobalContextStorage Ssl::TheGlobalContextStorage;

#include "ssl/ErrorDetail.h"
Security::ErrorCode parseErrorString(const char *name) STUB_RETVAL(0)
//const char *Ssl::getErrorName(Security::ErrorCode value) STUB_RETVAL(NULL)
Ssl::ErrorDetail::ErrorDetail(Security::ErrorCode, X509 *, X509 *, const char *) STUB
Ssl::ErrorDetail::ErrorDetail(ErrorDetail const &) STUB
const String & Ssl::ErrorDetail::toString() const STUB_RETSTATREF(String)

#include "ssl/support.h"
namespace Ssl
{
int AskPasswordCb(char *, int, int, void *) STUB_RETVAL(0)
bool InitServerContext(Security::ContextPointer &, AnyP::PortCfg &) STUB_RETVAL(false)
bool InitClientContext(Security::ContextPointer &, Security::PeerOptions &, const char *) STUB_RETVAL(false)
void SetupVerifyCallback(Security::ContextPointer &) STUB
void MaybeSetupRsaCallback(Security::ContextPointer &) STUB
} // namespace Ssl
const char *sslGetUserEmail(SSL *ssl) STUB_RETVAL(NULL)
const char *sslGetUserAttribute(SSL *ssl, const char *attribute_name) STUB_RETVAL(NULL)
const char *sslGetCAAttribute(SSL *ssl, const char *attribute_name) STUB_RETVAL(NULL)
SBuf sslGetUserCertificatePEM(SSL *ssl) STUB_RETVAL(SBuf())
SBuf sslGetUserCertificateChainPEM(SSL *ssl) STUB_RETVAL(SBuf())
namespace Ssl
{
//GETX509ATTRIBUTE GetX509UserAttribute;
//GETX509ATTRIBUTE GetX509CAAttribute;
//GETX509ATTRIBUTE GetX509Fingerprint;
std::vector<const char *> BumpModeStr = {""};
bool generateUntrustedCert(Security::CertPointer &, Security::PrivateKeyPointer &, Security::CertPointer const &, Security::PrivateKeyPointer const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContext(CertificateProperties const &, Security::ServerOptions &, bool) STUB_RETVAL(Security::ContextPointer())
bool verifySslCertificate(Security::ContextPointer &, CertificateProperties const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContextUsingPkeyAndCertFromMemory(const char *, Security::ServerOptions &, bool) STUB_RETVAL(Security::ContextPointer())
int matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data)) STUB_RETVAL(0)
bool checkX509ServerValidity(X509 *cert, const char *server) STUB_RETVAL(false)
int asn1timeToString(ASN1_TIME *tm, char *buf, int len) STUB_RETVAL(0)
void setClientSNI(SSL *ssl, const char *fqdn) STUB
SBuf GetX509PEM(SSL *ssl) STUB_RETVAL(SBuf())
} //namespace Ssl

#endif

