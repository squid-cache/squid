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
//Ssl::CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &) STUB
Ssl::CertificateStorageAction::Pointer Ssl::CertificateStorageAction::Create(const Mgr::Command::Pointer &) STUB_RETSTATREF(Ssl::CertificateStorageAction::Pointer)
void Ssl::CertificateStorageAction::dump(StoreEntry *) STUB
void Ssl::GlobalContextStorage::addLocalStorage(Ip::Address const &, size_t ) STUB
Ssl::LocalContextStorage *Ssl::GlobalContextStorage::getLocalStorage(Ip::Address const &)
{ fatal(STUB_API " required"); static LocalContextStorage v(0); return &v; }
void Ssl::GlobalContextStorage::reconfigureStart() STUB
//Ssl::GlobalContextStorage Ssl::TheGlobalContextStorage;

#include "ssl/ErrorDetail.h"
#include "ssl/support.h"
namespace Ssl
{
bool ParseErrorString(const char *, Security::Errors &) STUB_RETVAL(false)
int AskPasswordCb(char *, int, int, void *) STUB_RETVAL(0)
bool InitServerContext(Security::ContextPointer &, AnyP::PortCfg &) STUB_RETVAL(false)
bool InitClientContext(Security::ContextPointer &, Security::PeerOptions &, Security::ParsedPortFlags) STUB_RETVAL(false)
void ConfigurePeerVerification(Security::ContextPointer &, const Security::ParsedPortFlags) STUB
void DisablePeerVerification(Security::ContextPointer &) STUB
void MaybeSetupRsaCallback(Security::ContextPointer &) STUB
} // namespace Ssl
const char *sslGetUserEmail(SSL *) STUB_RETVAL(nullptr)
const char *sslGetUserAttribute(SSL *, const char *) STUB_RETVAL(nullptr)
const char *sslGetCAAttribute(SSL *, const char *) STUB_RETVAL(nullptr)
SBuf sslGetUserCertificatePEM(SSL *) STUB_RETVAL(SBuf())
SBuf sslGetUserCertificateChainPEM(SSL *) STUB_RETVAL(SBuf())
namespace Ssl
{
//GETX509ATTRIBUTE GetX509UserAttribute;
//GETX509ATTRIBUTE GetX509CAAttribute;
//GETX509ATTRIBUTE GetX509Fingerprint;
std::vector<const char *> BumpModeStr = {""};
bool generateUntrustedCert(Security::CertPointer &, Security::PrivateKeyPointer &, Security::CertPointer const &, Security::PrivateKeyPointer const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContext(CertificateProperties const &, Security::ServerOptions &, bool) STUB_RETVAL(Security::ContextPointer())
bool verifySslCertificate(const Security::ContextPointer &, CertificateProperties const &) STUB_RETVAL(false)
Security::ContextPointer GenerateSslContextUsingPkeyAndCertFromMemory(const char *, Security::ServerOptions &, bool) STUB_RETVAL(Security::ContextPointer())
int matchX509CommonNames(X509 *, void *, int (*)(void *,  ASN1_STRING *)) STUB_RETVAL(0)
bool checkX509ServerValidity(X509 *, const char *) STUB_RETVAL(false)
int asn1timeToString(ASN1_TIME *, char *, int) STUB_RETVAL(0)
void setClientSNI(SSL *, const char *) STUB
SBuf GetX509PEM(X509 *) STUB_RETVAL(SBuf())
} //namespace Ssl

#endif

