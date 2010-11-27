/*
 * 2009/01/17
 */

#ifndef SQUID_SSL_GADGETS_H
#define SQUID_SSL_GADGETS_H

#include "base/TidyPointer.h"

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif
#if HAVE_OPENSSL_TXT_DB_H
#include <openssl/txt_db.h>
#endif
#if HAVE_STRING
#include <string>
#endif

namespace Ssl
{
/**
 \defgroup SslCrtdSslAPI ssl_crtd SSL api.
 These functions must not depend on Squid runtime code such as debug()
 because they are used by ssl_crtd.
 */

/**
 \ingroup SslCrtdSslAPI
 * Function for BIO delete for Deleter template.
*/
void BIO_free_wrapper(BIO * bio);

/**
 \ingroup SslCrtdSslAPI
 * TidyPointer typedefs for  common SSL objects
 */
typedef TidyPointer<X509, X509_free> X509_Pointer;
typedef TidyPointer<EVP_PKEY, EVP_PKEY_free> EVP_PKEY_Pointer;
typedef TidyPointer<BIGNUM, BN_free> BIGNUM_Pointer;
typedef TidyPointer<BIO, BIO_free_wrapper> BIO_Pointer;
typedef TidyPointer<ASN1_INTEGER, ASN1_INTEGER_free> ASN1_INT_Pointer;
typedef TidyPointer<TXT_DB, TXT_DB_free> TXT_DB_Pointer;
typedef TidyPointer<X509_NAME, X509_NAME_free> X509_NAME_Pointer;
typedef TidyPointer<RSA, RSA_free> RSA_Pointer;
typedef TidyPointer<X509_REQ, X509_REQ_free> X509_REQ_Pointer;
typedef TidyPointer<SSL_CTX, SSL_CTX_free> SSL_CTX_Pointer;
typedef  TidyPointer<SSL, SSL_free> SSL_Pointer;


/**
 \ingroup SslCrtdSslAPI
 * Create 1024 bits rsa key.
 */
EVP_PKEY * createSslPrivateKey();

/**
 \ingroup SslCrtdSslAPI
 * Create request on certificate for a host.
 */
X509_REQ * createNewX509Request(EVP_PKEY_Pointer const & pkey, const char * hostname);

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to memory.
 */
bool writeCertAndPrivateKeyToMemory(X509_Pointer const & cert, EVP_PKEY_Pointer const & pkey, std::string & bufferToWrite);

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to file.
 */
bool writeCertAndPrivateKeyToFile(X509_Pointer const & cert, EVP_PKEY_Pointer const & pkey, char const * filename);

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to memory.
 */
bool readCertAndPrivateKeyFromMemory(X509_Pointer & cert, EVP_PKEY_Pointer & pkey, char const * bufferToRead);

/**
 \ingroup SslCrtdSslAPI
 * Sign SSL request.
 * \param x509 if this param equals NULL, returning certificate will be selfsigned.
 * \return X509 Signed certificate.
 */
X509 * signRequest(X509_REQ_Pointer const & request, X509_Pointer const & x509, EVP_PKEY_Pointer const & pkey, ASN1_TIME * timeNotAfter, BIGNUM const * serial);

/**
 \ingroup SslCrtdSslAPI
 * Decide on the kind of certificate and generate a CA- or self-signed one.
 * Return generated certificate and private key in resultX509 and resultPkey
 * variables.
 */
bool generateSslCertificateAndPrivateKey(char const *host, X509_Pointer const & signedX509, EVP_PKEY_Pointer const & signedPkey, X509_Pointer & cert, EVP_PKEY_Pointer & pkey, BIGNUM const* serial);

/**
 \ingroup SslCrtdSslAPI
 *  Read certificate and private key from files.
 * \param certFilename name of file with certificate.
 * \param keyFilename name of file with private key.
 */
void readCertAndPrivateKeyFromFiles(X509_Pointer & cert, EVP_PKEY_Pointer & pkey, char const * certFilename, char const * keyFilename);

/**
 \ingroup SslCrtdSslAPI
 * Verify date. Date format it ASN1_UTCTIME. if there is out of date error,
 * return false.
*/
bool sslDateIsInTheFuture(char const * date);

} // namespace Ssl
#endif // SQUID_SSL_GADGETS_H
