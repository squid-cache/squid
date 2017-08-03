/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "fatal.h"

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
bool InitServerContext(Security::ContextPointer &, AnyP::PortCfg &) STUB_RETVAL(false)
bool InitClientContext(Security::ContextPointer &, Security::PeerOptions &, const char *) STUB_RETVAL(false)
} // namespace Ssl
const char *sslGetUserEmail(SSL *ssl) STUB_RETVAL(NULL)
const char *sslGetUserAttribute(SSL *ssl, const char *attribute_name) STUB_RETVAL(NULL)
const char *sslGetCAAttribute(SSL *ssl, const char *attribute_name) STUB_RETVAL(NULL)
const char *sslGetUserCertificatePEM(SSL *ssl) STUB_RETVAL(NULL)
const char *sslGetUserCertificateChainPEM(SSL *ssl) STUB_RETVAL(NULL)
namespace Ssl
{
//GETX509ATTRIBUTE GetX509UserAttribute;
//GETX509ATTRIBUTE GetX509CAAttribute;
//GETX509ATTRIBUTE GetX509Fingerprint;
std::vector<const char *> BumpModeStr = {""};
bool generateUntrustedCert(Security::CertPointer & untrustedCert, EVP_PKEY_Pointer & untrustedPkey, Security::CertPointer const & cert, EVP_PKEY_Pointer const & pkey) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContext(CertificateProperties const &, AnyP::PortCfg &, bool) STUB_RETVAL(Security::ContextPointer())
bool verifySslCertificate(Security::ContextPointer &, CertificateProperties const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContextUsingPkeyAndCertFromMemory(const char *, AnyP::PortCfg &, bool) STUB_RETVAL(Security::ContextPointer())
void addChainToSslContext(Security::ContextPointer &, STACK_OF(X509) *) STUB
void readCertChainAndPrivateKeyFromFiles(Security::CertPointer & cert, EVP_PKEY_Pointer & pkey, X509_STACK_Pointer & chain, char const * certFilename, char const * keyFilename) STUB
int matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data)) STUB_RETVAL(0)
bool checkX509ServerValidity(X509 *cert, const char *server) STUB_RETVAL(false)
int asn1timeToString(ASN1_TIME *tm, char *buf, int len) STUB_RETVAL(0)
bool setClientSNI(SSL *ssl, const char *fqdn) STUB_RETVAL(false)
} //namespace Ssl

#endif

