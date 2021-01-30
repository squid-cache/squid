/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL accelerator support */

#ifndef SQUID_SSL_SUPPORT_H
#define SQUID_SSL_SUPPORT_H

#if USE_OPENSSL

#include "base/CbDataList.h"
#include "comm/forward.h"
#include "compat/openssl.h"
#include "sbuf/SBuf.h"
#include "security/forward.h"
#include "ssl/gadgets.h"

#if HAVE_OPENSSL_X509V3_H
#include <openssl/x509v3.h>
#endif
#if HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#if HAVE_OPENSSL_ENGINE_H
#include <openssl/engine.h>
#endif
#include <queue>
#include <map>

/**
 \defgroup ServerProtocolSSLAPI Server-Side SSL API
 \ingroup ServerProtocol
 */

// Custom SSL errors; assumes all official errors are positive
#define SQUID_X509_V_ERR_INFINITE_VALIDATION -4
#define SQUID_X509_V_ERR_CERT_CHANGE -3
#define SQUID_ERR_SSL_HANDSHAKE -2
#define SQUID_X509_V_ERR_DOMAIN_MISMATCH -1
// All SSL errors range: from smallest (negative) custom to largest SSL error
#define SQUID_SSL_ERROR_MIN SQUID_X509_V_ERR_CERT_CHANGE
#define SQUID_SSL_ERROR_MAX INT_MAX

// Maximum certificate validation callbacks. OpenSSL versions exceeding this
// limit are deemed stuck in an infinite validation loop (OpenSSL bug #3090)
// and will trigger the SQUID_X509_V_ERR_INFINITE_VALIDATION error.
// Can be set to a number up to UINT32_MAX
#ifndef SQUID_CERT_VALIDATION_ITERATION_MAX
#define SQUID_CERT_VALIDATION_ITERATION_MAX 16384
#endif

namespace AnyP
{
class PortCfg;
};

namespace Ipc
{
class MemMap;
}

namespace Ssl
{

/// callback for receiving password to access password secured PEM files
/// XXX: Requires SSL_CTX_set_default_passwd_cb_userdata()!
int AskPasswordCb(char *buf, int size, int rwflag, void *userdata);

/// initialize the SSL library global state.
/// call before generating any SSL context
void Initialize();

class ErrorDetail;
class CertValidationResponse;
typedef RefCount<CertValidationResponse> CertValidationResponsePointer;

/// initialize a TLS server context with OpenSSL specific settings
bool InitServerContext(Security::ContextPointer &, AnyP::PortCfg &);

/// initialize a TLS client context with OpenSSL specific settings
bool InitClientContext(Security::ContextPointer &, Security::PeerOptions &, long flags);

/// set the certificate verify callback for a context
void SetupVerifyCallback(Security::ContextPointer &);

/// if required, setup callback for generating ephemeral RSA keys
void MaybeSetupRsaCallback(Security::ContextPointer &);

} //namespace Ssl

/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserEmail(SSL *ssl);

/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserAttribute(SSL *ssl, const char *attribute_name);

/// \ingroup ServerProtocolSSLAPI
const char *sslGetCAAttribute(SSL *ssl, const char *attribute_name);

/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserCertificatePEM(SSL *ssl);

/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserCertificateChainPEM(SSL *ssl);

namespace Ssl
{
/// \ingroup ServerProtocolSSLAPI
typedef char const *GETX509ATTRIBUTE(X509 *, const char *);

/// \ingroup ServerProtocolSSLAPI
GETX509ATTRIBUTE GetX509UserAttribute;

/// \ingroup ServerProtocolSSLAPI
GETX509ATTRIBUTE GetX509CAAttribute;

/// \ingroup ServerProtocolSSLAPI
GETX509ATTRIBUTE GetX509Fingerprint;

extern const EVP_MD *DefaultSignHash;

/**
  \ingroup ServerProtocolSSLAPI
 * Supported ssl-bump modes
 */
enum BumpMode {bumpNone = 0, bumpClientFirst, bumpServerFirst, bumpPeek, bumpStare, bumpBump, bumpSplice, bumpTerminate, /*bumpErr,*/ bumpEnd};

enum BumpStep {bumpStep1, bumpStep2, bumpStep3};

/**
 \ingroup  ServerProtocolSSLAPI
 * Short names for ssl-bump modes
 */
extern std::vector<const char *>BumpModeStr;

/**
 \ingroup ServerProtocolSSLAPI
 * Return the short name of the ssl-bump mode "bm"
 */
inline const char *bumpMode(int bm)
{
    return (0 <= bm && bm < Ssl::bumpEnd) ? Ssl::BumpModeStr.at(bm) : NULL;
}

/// certificates indexed by issuer name
typedef std::multimap<SBuf, X509 *> CertsIndexedList;

/**
 * Load PEM-encoded certificates from the given file.
 */
bool loadCerts(const char *certsFile, Ssl::CertsIndexedList &list);

/**
 * Load PEM-encoded certificates to the squid untrusteds certificates
 * internal DB from the given file.
 */
bool loadSquidUntrusted(const char *path);

/**
 * Removes all certificates from squid untrusteds certificates
 * internal DB and frees all memory
 */
void unloadSquidUntrusted();

/**
 * Add the certificate cert to ssl object untrusted certificates.
 * Squid uses an attached to SSL object list of untrusted certificates,
 * with certificates which can be used to complete incomplete chains sent
 * by the SSL server.
 */
void SSL_add_untrusted_cert(SSL *ssl, X509 *cert);

/**
 * Searches in serverCertificates list for the cert issuer and if not found
 * and Authority Info Access of cert provides a URI return it.
 */
const char *uriOfIssuerIfMissing(X509 *cert,  Security::CertList const &serverCertificates, const Security::ContextPointer &context);

/**
 * Fill URIs queue with the uris of missing certificates from serverCertificate chain
 * if this information provided by Authority Info Access.
 */
void missingChainCertificatesUrls(std::queue<SBuf> &URIs, Security::CertList const &serverCertificates, const Security::ContextPointer &context);

/**
  \ingroup ServerProtocolSSLAPI
  * Generate a certificate to be used as untrusted signing certificate, based on a trusted CA
*/
bool generateUntrustedCert(Security::CertPointer & untrustedCert, Security::PrivateKeyPointer & untrustedPkey, Security::CertPointer const & cert, Security::PrivateKeyPointer const & pkey);

/// certificates indexed by issuer name
typedef std::multimap<SBuf, X509 *> CertsIndexedList;

/**
 \ingroup ServerProtocolSSLAPI
 * Load PEM-encoded certificates from the given file.
 */
bool loadCerts(const char *certsFile, Ssl::CertsIndexedList &list);

/**
 \ingroup ServerProtocolSSLAPI
 * Load PEM-encoded certificates to the squid untrusteds certificates
 * internal DB from the given file.
 */
bool loadSquidUntrusted(const char *path);

/**
 \ingroup ServerProtocolSSLAPI
 * Removes all certificates from squid untrusteds certificates
 * internal DB and frees all memory
 */
void unloadSquidUntrusted();

/**
  \ingroup ServerProtocolSSLAPI
  * Decide on the kind of certificate and generate a CA- or self-signed one
*/
Security::ContextPointer GenerateSslContext(CertificateProperties const &, Security::ServerOptions &, bool trusted);

/**
  \ingroup ServerProtocolSSLAPI
  * Check if the certificate of the given context is still valid
  \param sslContext The context to check
  \param properties Check if the context certificate matches the given properties
  \return true if the contexts certificate is valid, false otherwise
 */
bool verifySslCertificate(Security::ContextPointer &, CertificateProperties const &);

/**
  \ingroup ServerProtocolSSLAPI
  * Read private key and certificate from memory and generate SSL context
  * using their.
 */
Security::ContextPointer GenerateSslContextUsingPkeyAndCertFromMemory(const char * data, Security::ServerOptions &, bool trusted);

/**
  \ingroup ServerProtocolSSLAPI
  * Create an SSL context using the provided certificate and key
 */
Security::ContextPointer createSSLContext(Security::CertPointer & x509, Security::PrivateKeyPointer & pkey, Security::ServerOptions &);

/**
 \ingroup ServerProtocolSSLAPI
 * Chain signing certificate and chained certificates to an SSL Context
 */
void chainCertificatesToSSLContext(Security::ContextPointer &, Security::ServerOptions &);

/**
 \ingroup ServerProtocolSSLAPI
 * Configure a previously unconfigured SSL context object.
 */
void configureUnconfiguredSslContext(Security::ContextPointer &, Ssl::CertSignAlgorithm signAlgorithm, AnyP::PortCfg &);

/**
  \ingroup ServerProtocolSSLAPI
  * Generates a certificate and a private key using provided properies and set it
  * to SSL object.
 */
bool configureSSL(SSL *ssl, CertificateProperties const &properties, AnyP::PortCfg &port);

/**
  \ingroup ServerProtocolSSLAPI
  * Read private key and certificate from memory and set it to SSL object
  * using their.
 */
bool configureSSLUsingPkeyAndCertFromMemory(SSL *ssl, const char *data, AnyP::PortCfg &port);

/**
  \ingroup ServerProtocolSSLAPI
  * Configures sslContext to use squid untrusted certificates internal list
  * to complete certificate chains when verifies SSL servers certificates.
 */
void useSquidUntrusted(SSL_CTX *sslContext);

/**
   \ingroup ServerProtocolSSLAPI
   * Iterates over the X509 common and alternate names and to see if  matches with given data
   * using the check_func.
   \param peer_cert  The X509 cert to check
   \param check_data The data with which the X509 CNs compared
   \param check_func The function used to match X509 CNs. The CN data passed as ASN1_STRING data
   \return   1 if any of the certificate CN matches, 0 if none matches.
 */
int matchX509CommonNames(X509 *peer_cert, void *check_data, int (*check_func)(void *check_data,  ASN1_STRING *cn_data));

/**
   \ingroup ServerProtocolSSLAPI
   * Check if the certificate is valid for a server
   \param cert  The X509 cert to check.
   \param server The server name.
   \return   true if the certificate is valid for the server or false otherwise.
 */
bool checkX509ServerValidity(X509 *cert, const char *server);

/**
   \ingroup ServerProtocolSSLAPI
   * Convert a given ASN1_TIME to a string form.
   \param tm the time in ASN1_TIME form
   \param buf the buffer to write the output
   \param len write at most len bytes
   \return The number of bytes written
 */
int asn1timeToString(ASN1_TIME *tm, char *buf, int len);

/**
   \ingroup ServerProtocolSSLAPI
   * Sets the hostname for the Server Name Indication (SNI) TLS extension
   * if supported by the used openssl toolkit.
*/
void setClientSNI(SSL *ssl, const char *fqdn);

/**
  \ingroup ServerProtocolSSLAPI
  * Generates a unique key based on CertificateProperties object and store it to key
 */
void InRamCertificateDbKey(const Ssl::CertificateProperties &certProperties, SBuf &key);

/**
  \ingroup ServerProtocolSSLAPI
  Creates and returns an OpenSSL BIO object for writing to `buf` (or throws).
  TODO: Add support for reading from `buf`.
 */
BIO *BIO_new_SBuf(SBuf *buf);
} //namespace Ssl

#if _SQUID_WINDOWS_

#if defined(__cplusplus)

/** \cond AUTODOCS-IGNORE */
namespace Squid
{
/** \endcond */

/// \ingroup ServerProtocolSSLAPI
inline
int SSL_set_fd(SSL *ssl, int fd)
{
    return ::SSL_set_fd(ssl, _get_osfhandle(fd));
}

/// \ingroup ServerProtocolSSLAPI
#define SSL_set_fd(ssl,fd) Squid::SSL_set_fd(ssl,fd)

} /* namespace Squid */

#else

/// \ingroup ServerProtocolSSLAPI
#define SSL_set_fd(s,f) (SSL_set_fd(s, _get_osfhandle(f)))

#endif /* __cplusplus */

#endif /* _SQUID_WINDOWS_ */

#endif /* USE_OPENSSL */
#endif /* SQUID_SSL_SUPPORT_H */

