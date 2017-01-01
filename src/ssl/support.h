/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL accelerator support */

#ifndef SQUID_SSL_SUPPORT_H
#define SQUID_SSL_SUPPORT_H

#include "CbDataList.h"
#include "SBuf.h"
#include "ssl/gadgets.h"

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif
#if HAVE_OPENSSL_X509V3_H
#include <openssl/x509v3.h>
#endif
#if HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#if HAVE_OPENSSL_ENGINE_H
#include <openssl/engine.h>
#endif
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

namespace Ssl
{
/// Squid defined error code (<0),  an error code returned by SSL X509 api, or SSL_ERROR_NONE
typedef int ssl_error_t;

typedef CbDataList<Ssl::ssl_error_t> Errors;

/// Creates SSL Client connection structure and initializes SSL I/O (Comm and BIO).
/// On errors, emits DBG_IMPORTANT with details and returns NULL.
SSL *CreateClient(SSL_CTX *sslContext, const int fd, const char *squidCtx);

/// Creates SSL Server connection structure and initializes SSL I/O (Comm and BIO).
/// On errors, emits DBG_IMPORTANT with details and returns NULL.
SSL *CreateServer(SSL_CTX *sslContext, const int fd, const char *squidCtx);

/// An SSL certificate-related error.
/// Pairs an error code with the certificate experiencing the error.
class CertError
{
public:
    ssl_error_t code; ///< certificate error code
    X509_Pointer cert; ///< certificate with the above error code
    CertError(ssl_error_t anErr, X509 *aCert);
    CertError(CertError const &err);
    CertError & operator = (const CertError &old);
    bool operator == (const CertError &ce) const;
    bool operator != (const CertError &ce) const;
};

/// Holds a list of certificate SSL errors
typedef CbDataList<Ssl::CertError> CertErrors;

} //namespace Ssl

/// \ingroup ServerProtocolSSLAPI
SSL_CTX *sslCreateServerContext(AnyP::PortCfg &port);

/// \ingroup ServerProtocolSSLAPI
SSL_CTX *sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath, const char *CRLfile);

/// \ingroup ServerProtocolSSLAPI
int ssl_read_method(int, char *, int);

/// \ingroup ServerProtocolSSLAPI
int ssl_write_method(int, const char *, int);

/// \ingroup ServerProtocolSSLAPI
void ssl_shutdown_method(SSL *ssl);

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
extern const char *BumpModeStr[];

/**
 \ingroup ServerProtocolSSLAPI
 * Return the short name of the ssl-bump mode "bm"
 */
inline const char *bumpMode(int bm)
{
    return (0 <= bm && bm < Ssl::bumpEnd) ? Ssl::BumpModeStr[bm] : NULL;
}

/**
 \ingroup ServerProtocolSSLAPI
 * Parses the SSL flags.
 */
long parse_flags(const char *flags);

/**
 \ingroup ServerProtocolSSLAPI
 * Parses the SSL options.
 */
long parse_options(const char *options);

/**
 \ingroup ServerProtocolSSLAPI
 * Load a CRLs list stored in a file
 */
STACK_OF(X509_CRL) *loadCrl(const char *CRLFile, long &flags);

/**
 \ingroup ServerProtocolSSLAPI
 * Load DH params from file
 */
DH *readDHParams(const char *dhfile);

/**
 \ingroup ServerProtocolSSLAPI
 * Compute the Ssl::ContextMethod (SSL_METHOD) from SSL version
 */
ContextMethod contextMethod(int version);

/**
  \ingroup ServerProtocolSSLAPI
  * Generate a certificate to be used as untrusted signing certificate, based on a trusted CA
*/
bool generateUntrustedCert(X509_Pointer & untrustedCert, EVP_PKEY_Pointer & untrustedPkey, X509_Pointer const & cert, EVP_PKEY_Pointer const & pkey);

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
SSL_CTX * generateSslContext(CertificateProperties const &properties, AnyP::PortCfg &port);

/**
  \ingroup ServerProtocolSSLAPI
  * Check if the certificate of the given context is still valid
  \param sslContext The context to check
  \param properties Check if the context certificate matches the given properties
  \return true if the contexts certificate is valid, false otherwise
 */
bool verifySslCertificate(SSL_CTX * sslContext,  CertificateProperties const &properties);

/**
  \ingroup ServerProtocolSSLAPI
  * Read private key and certificate from memory and generate SSL context
  * using their.
 */
SSL_CTX * generateSslContextUsingPkeyAndCertFromMemory(const char * data, AnyP::PortCfg &port);

/**
  \ingroup ServerProtocolSSLAPI
  * Create an SSL context using the provided certificate and key
 */
SSL_CTX * createSSLContext(Ssl::X509_Pointer & x509, Ssl::EVP_PKEY_Pointer & pkey, AnyP::PortCfg &port);

/**
 \ingroup ServerProtocolSSLAPI
 * Chain signing certificate and chained certificates to an SSL Context
 */
void chainCertificatesToSSLContext(SSL_CTX *sslContext, AnyP::PortCfg &port);

/**
 \ingroup ServerProtocolSSLAPI
 * Configure a previously unconfigured SSL context object.
 */
void configureUnconfiguredSslContext(SSL_CTX *sslContext, Ssl::CertSignAlgorithm signAlgorithm,AnyP::PortCfg &port);

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
  * Adds the certificates in certList to the certificate chain of the SSL context
 */
void addChainToSslContext(SSL_CTX *sslContext, STACK_OF(X509) *certList);

/**
  \ingroup ServerProtocolSSLAPI
  * Configures sslContext to use squid untrusted certificates internal list
  * to complete certificate chains when verifies SSL servers certificates.
 */
void useSquidUntrusted(SSL_CTX *sslContext);

/**
 \ingroup ServerProtocolSSLAPI
 *  Read certificate, private key and any certificates which must be chained from files.
 * See also: Ssl::readCertAndPrivateKeyFromFiles function,  defined in gadgets.h
 * \param certFilename name of file with certificate and certificates which must be chainned.
 * \param keyFilename name of file with private key.
 */
void readCertChainAndPrivateKeyFromFiles(X509_Pointer & cert, EVP_PKEY_Pointer & pkey, X509_STACK_Pointer & chain, char const * certFilename, char const * keyFilename);

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
   \return true if SNI set false otherwise
*/
bool setClientSNI(SSL *ssl, const char *fqdn);

int OpenSSLtoSquidSSLVersion(int sslVersion);

#if OPENSSL_VERSION_NUMBER < 0x00909000L
SSL_METHOD *method(int version);
#else
const SSL_METHOD *method(int version);
#endif

const SSL_METHOD *serverMethod(int version);

/**
   \ingroup ServerProtocolSSLAPI
   * Initializes the shared session cache if configured
*/
void initialize_session_cache();

/**
   \ingroup ServerProtocolSSLAPI
   * Destroy the shared session cache if configured
*/
void destruct_session_cache();
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

#endif /* SQUID_SSL_SUPPORT_H */

