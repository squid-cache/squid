#include "squid.h"

#if USE_SSL

#include "fatal.h"

/* Stub File for the ssl/libsslsquid.la convenience library */

#define STUB_API "ssl/libsslsquid.la"
#include "tests/STUB.h"

#include "ssl/Config.h"
Ssl::Config::Config() { printf("Ssl::Config::Config No implemented\n"); }
Ssl::Config::~Config() { printf("Ssl::Config::Config No implemented\n"); }
Ssl::Config Ssl::TheConfig;

#include "ssl/context_storage.h"
//Ssl::CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &cmd) STUB
Ssl::CertificateStorageAction::Pointer Ssl::CertificateStorageAction::Create(const Mgr::Command::Pointer &cmd) STUB_RETSTATREF(Ssl::CertificateStorageAction::Pointer)
void Ssl::CertificateStorageAction::dump(StoreEntry *sentry) STUB
Ssl::LocalContextStorage::Item::Item(SSL_CTX * aSsl_ctx, std::string const & aName) STUB
Ssl::LocalContextStorage::Item::~Item() STUB
Ssl::LocalContextStorage::LocalContextStorage(size_t aMax_memory) STUB
Ssl::LocalContextStorage::~LocalContextStorage() STUB
void Ssl::LocalContextStorage::SetSize(size_t aMax_memory) STUB
SSL_CTX * Ssl::LocalContextStorage::add(char const * host_name, SSL_CTX * ssl_ctx) STUB_RETVAL(NULL)
SSL_CTX * Ssl::LocalContextStorage::find(char const * host_name) STUB_RETVAL(NULL)
void Ssl::LocalContextStorage::remove(char const * host_name) STUB
//Ssl::GlobalContextStorage::GlobalContextStorage() STUB
//Ssl::GlobalContextStorage::~GlobalContextStorage() STUB
void Ssl::GlobalContextStorage::addLocalStorage(Ip::Address const & address, size_t size_of_store) STUB
Ssl::LocalContextStorage & Ssl::GlobalContextStorage::getLocalStorage(Ip::Address const & address)
{ fatal(STUB_API " required"); static Ssl::LocalContextStorage v(0); return v; }
void Ssl::GlobalContextStorage::reconfigureStart() STUB
//Ssl::GlobalContextStorage Ssl::TheGlobalContextStorage;

#include "ssl/ErrorDetail.h"
Ssl::ssl_error_t parseErrorString(const char *name) STUB_RETVAL(0)
//const char *Ssl::getErrorName(ssl_error_t value) STUB_RETVAL(NULL)
Ssl::ErrorDetail::ErrorDetail(ssl_error_t err_no, X509 *, X509 *) STUB
Ssl::ErrorDetail::ErrorDetail(ErrorDetail const &) STUB
const String & Ssl::ErrorDetail::toString() const STUB_RETSTATREF(String)

#include "ssl/support.h"
SSL_CTX *sslCreateServerContext(AnyP::PortCfg &) STUB_RETVAL(NULL)
SSL_CTX *sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath, const char *CRLfile) STUB_RETVAL(NULL)
int ssl_read_method(int, char *, int) STUB_RETVAL(0)
int ssl_write_method(int, const char *, int) STUB_RETVAL(0)
void ssl_shutdown_method(SSL *) STUB
const char *sslGetUserEmail(SSL *ssl) STUB_RETVAL(NULL)
// typedef char const *SSLGETATTRIBUTE(SSL *, const char *);
// SSLGETATTRIBUTE sslGetUserAttribute;
// SSLGETATTRIBUTE sslGetCAAttribute;
const char *sslGetUserCertificatePEM(SSL *ssl) STUB_RETVAL(NULL)
const char *sslGetUserCertificateChainPEM(SSL *ssl) STUB_RETVAL(NULL)
SSL_CTX * Ssl::generateSslContext(CertificateProperties const &properties, AnyP::PortCfg &) STUB_RETVAL(NULL)
SSL_CTX * Ssl::generateSslContextUsingPkeyAndCertFromMemory(const char * data, AnyP::PortCfg &) STUB_RETVAL(NULL)
int Ssl::matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data)) STUB_RETVAL(0)
int Ssl::asn1timeToString(ASN1_TIME *tm, char *buf, int len) STUB_RETVAL(0)

#endif
