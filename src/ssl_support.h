
/*
 * $Id$
 *
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

#include "config.h"
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

/// \ingroup ServerProtocolSSLAPI
SSL_CTX *sslCreateServerContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *clientCA, const char *CAfile, const char *CApath, const char *CRLfile, const char *dhpath, const char *context);

/// \ingroup ServerProtocolSSLAPI
SSL_CTX *sslCreateClientContext(const char *certfile, const char *keyfile, int version, const char *cipher, const char *options, const char *flags, const char *CAfile, const char *CApath, const char *CRLfile);

/// \ingroup ServerProtocolSSLAPI
int ssl_read_method(int, char *, int);

/// \ingroup ServerProtocolSSLAPI
int ssl_write_method(int, const char *, int);

/// \ingroup ServerProtocolSSLAPI
void ssl_shutdown_method(int);


/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserEmail(SSL *ssl);

/// \ingroup ServerProtocolSSLAPI
typedef char const *SSLGETATTRIBUTE(SSL *, const char *);

/// \ingroup ServerProtocolSSLAPI
SSLGETATTRIBUTE sslGetUserAttribute;

/// \ingroup ServerProtocolSSLAPI
SSLGETATTRIBUTE sslGetCAAttribute;

/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserCertificatePEM(SSL *ssl);

/// \ingroup ServerProtocolSSLAPI
const char *sslGetUserCertificateChainPEM(SSL *ssl);

namespace Ssl
{
/**
  \ingroup ServerProtocolSSLAPI
  * Decide on the kind of certificate and generate a CA- or self-signed one
*/
SSL_CTX *generateSslContext(char const *host, Ssl::X509_Pointer const & signedX509, Ssl::EVP_PKEY_Pointer const & signedPkey);

/**
  \ingroup ServerProtocolSSLAPI
  * Check date of certificate signature. If there is out of date error fucntion
  * returns false, true otherwise.
 */
bool verifySslCertificateDate(SSL_CTX * sslContext);

/**
  \ingroup ServerProtocolSSLAPI
  * Read private key and certificate from memory and generate SSL context
  * using their.
 */
SSL_CTX * generateSslContextUsingPkeyAndCertFromMemory(const char * data);

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
   * Convert a given ASN1_TIME to a string form.
   \param tm the time in ASN1_TIME form
   \param buf the buffer to write the output
   \param len write at most len bytes
   \return The number of bytes written
 */
int asn1timeToString(ASN1_TIME *tm, char *buf, int len);

} //namespace Ssl

#ifdef _SQUID_MSWIN_

#ifdef __cplusplus

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

#endif /* _SQUID_MSWIN_ */

#endif /* SQUID_SSL_SUPPORT_H */
