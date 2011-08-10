#include "config.h"
#include "fatal.h"

/* Stub File for the ssl/libsslsquid.la convenience library */

#define STUB_BASE "ssl/libsslsquid.la"

#define STUB { fatal(STUB_BASE " required."); }
#define STUB_RETVAL(x) { fatal(STUB_BASE " required."); return (x); }
#define STUB_RETREF(x) { fatal(STUB_BASE " required."); static x v; return v; }
#define STUB_RETREF2(x,y) { fatal(STUB_BASE " required."); static x v((y)); return v; }

#include "ssl/Config.h"
Ssl::Config::Config() STUB
Ssl::Config::~Config() STUB
Ssl::Config Ssl::TheConfig;

#include "ssl/context_storage.h"
//Ssl::CertificateStorageAction::CertificateStorageAction(const Mgr::Command::Pointer &cmd) STUB
Ssl::CertificateStorageAction::Pointer Ssl::CertificateStorageAction::Create(const Mgr::Command::Pointer &cmd) STUB_RETREF(Ssl::CertificateStorageAction::Pointer)
void Ssl::CertificateStorageAction::dump(StoreEntry *sentry) STUB
Ssl::LocalContextStorage::Item::Item(SSL_CTX * aSsl_ctx, std::string const & aName) STUB
Ssl::LocalContextStorage::Item::~Item() STUB
Ssl::LocalContextStorage::LocalContextStorage(size_t aMax_memory) STUB
Ssl::LocalContextStorage::~LocalContextStorage() STUB
void Ssl::LocalContextStorage::SetSize(size_t aMax_memory) STUB
SSL_CTX * Ssl::LocalContextStorage::add(char const * host_name, SSL_CTX * ssl_ctx) STUB_RETVAL(NULL)
SSL_CTX * Ssl::LocalContextStorage::find(char const * host_name) STUB_RETVAL(NULL)
void Ssl::LocalContextStorage::remove(char const * host_name) STUB
Ssl::GlobalContextStorage::GlobalContextStorage() STUB
Ssl::GlobalContextStorage::~GlobalContextStorage() STUB
void Ssl::GlobalContextStorage::addLocalStorage(Ip::Address const & address, size_t size_of_store) STUB
Ssl::LocalContextStorage & Ssl::GlobalContextStorage::getLocalStorage(Ip::Address const & address) STUB_RETREF2(Ssl::LocalContextStorage, 0)
void Ssl::GlobalContextStorage::reconfigureStart() STUB
//Ssl::GlobalContextStorage Ssl::TheGlobalContextStorage;

#include "ssl/ErrorDetail.h"
Ssl::ssl_error_t parseErrorString(const char *name) STUB_RETVAL(0)
const char *Ssl::getErrorName(ssl_error_t value) STUB_RETVAL(NULL)
Ssl::ErrorDetail::ErrorDetail(ssl_error_t err_no, X509 *cert) STUB
Ssl::ErrorDetail::ErrorDetail(ErrorDetail const &) STUB
const String & Ssl::ErrorDetail::toString() const STUB_RETREF(String)

#include "ssl/support.h"
SSL_CTX *sslCreateServerContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *clientCA, const char *CAfile, const char *CApath, const char *CRLfile, const char *dhpath, const char *context) STUB_RETVAL(NULL)
SSL_CTX *sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath, const char *CRLfile) STUB_RETVAL(NULL)
int ssl_read_method(int, char *, int) STUB_RETVAL(0)
int ssl_write_method(int, const char *, int) STUB_RETVAL(0)
void ssl_shutdown_method(int) STUB
const char *sslGetUserEmail(SSL *ssl) STUB_RETVAL(NULL)
// typedef char const *SSLGETATTRIBUTE(SSL *, const char *);
// SSLGETATTRIBUTE sslGetUserAttribute;
// SSLGETATTRIBUTE sslGetCAAttribute;
const char *sslGetUserCertificatePEM(SSL *ssl) STUB_RETVAL(NULL)
const char *sslGetUserCertificateChainPEM(SSL *ssl) STUB_RETVAL(NULL)
SSL_CTX *Ssl::generateSslContext(char const *host, Ssl::X509_Pointer const & signedX509, Ssl::EVP_PKEY_Pointer const & signedPkey) STUB_RETVAL(NULL)
bool Ssl::verifySslCertificateDate(SSL_CTX * sslContext) STUB_RETVAL(false)
SSL_CTX * Ssl::generateSslContextUsingPkeyAndCertFromMemory(const char * data) STUB_RETVAL(NULL)
int Ssl::matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data)) STUB_RETVAL(0)
int Ssl::asn1timeToString(ASN1_TIME *tm, char *buf, int len) STUB_RETVAL(0)
