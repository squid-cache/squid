
/*
 * AUTHOR: Benno Rice
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#ifndef SQUID_SSL_SUPPORT_H
#define SQUID_SSL_SUPPORT_H

#include "CbDataList.h"
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

/**
  \ingroup ServerProtocolSSLAPI
 * Supported ssl-bump modes
 */
enum BumpMode {bumpNone = 0, bumpClientFirst, bumpServerFirst, bumpEnd};

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
  * Adds the certificates in certList to the certificate chain of the SSL context
 */
void addChainToSslContext(SSL_CTX *sslContext, STACK_OF(X509) *certList);

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
