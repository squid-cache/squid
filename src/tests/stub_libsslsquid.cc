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
Ssl::ssl_error_t parseErrorString(const char *name) STUB_RETVAL(0)
//const char *Ssl::getErrorName(ssl_error_t value) STUB_RETVAL(NULL)
Ssl::ErrorDetail::ErrorDetail(ssl_error_t err_no, X509 *, X509 *, const char *) STUB
Ssl::ErrorDetail::ErrorDetail(ErrorDetail const &) STUB
const String & Ssl::ErrorDetail::toString() const STUB_RETSTATREF(String)

#include "ssl/support.h"
namespace Ssl
{
//CertError::CertError(ssl_error_t anErr, X509 *aCert) STUB
//CertError::CertError(CertError const &err) STUB
CertError & CertError::operator = (const CertError &old) STUB_RETVAL(*this)
bool CertError::operator == (const CertError &ce) const STUB_RETVAL(false)
bool CertError::operator != (const CertError &ce) const STUB_RETVAL(false)
} // namespace Ssl
SSL_CTX *sslCreateServerContext(AnyP::PortCfg &port) STUB_RETVAL(NULL)
SSL_CTX *sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath, const char *CRLfile) STUB_RETVAL(NULL)
int ssl_read_method(int, char *, int) STUB_RETVAL(0)
int ssl_write_method(int, const char *, int) STUB_RETVAL(0)
void ssl_shutdown_method(SSL *ssl) STUB
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
const char *BumpModeStr[] = {""};
long parse_flags(const char *flags) STUB_RETVAL(0)
long parse_options(const char *options) STUB_RETVAL(0)
STACK_OF(X509_CRL) *loadCrl(const char *CRLFile, long &flags) STUB_RETVAL(NULL)
DH *readDHParams(const char *dhfile) STUB_RETVAL(NULL)
ContextMethod contextMethod(int version) STUB_RETVAL(ContextMethod())
bool generateUntrustedCert(X509_Pointer & untrustedCert, EVP_PKEY_Pointer & untrustedPkey, X509_Pointer const & cert, EVP_PKEY_Pointer const & pkey) STUB_RETVAL(false)
SSL_CTX * generateSslContext(CertificateProperties const &properties, AnyP::PortCfg &port) STUB_RETVAL(NULL)
bool verifySslCertificate(SSL_CTX * sslContext,  CertificateProperties const &properties) STUB_RETVAL(false)
SSL_CTX * generateSslContextUsingPkeyAndCertFromMemory(const char * data, AnyP::PortCfg &port) STUB_RETVAL(NULL)
void addChainToSslContext(SSL_CTX *sslContext, STACK_OF(X509) *certList) STUB
void readCertChainAndPrivateKeyFromFiles(X509_Pointer & cert, EVP_PKEY_Pointer & pkey, X509_STACK_Pointer & chain, char const * certFilename, char const * keyFilename) STUB
int matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data)) STUB_RETVAL(0)
bool checkX509ServerValidity(X509 *cert, const char *server) STUB_RETVAL(false)
int asn1timeToString(ASN1_TIME *tm, char *buf, int len) STUB_RETVAL(0)
bool setClientSNI(SSL *ssl, const char *fqdn) STUB_RETVAL(false)
void initialize_session_cache() STUB
void destruct_session_cache() STUB
} //namespace Ssl

#endif

