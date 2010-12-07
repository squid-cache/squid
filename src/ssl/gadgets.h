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

// Macro to be used to define the C++ equivalent function of an extern "C"
// function. The C++ function suffixed with the _cpp extension
#define CtoCpp1(function, argument) \
        extern "C++" inline void function ## _cpp(argument a) { \
            function(a); \
        }

/**
 \ingroup SslCrtdSslAPI
 * TidyPointer typedefs for  common SSL objects
 */
CtoCpp1(X509_free, X509 *)
typedef TidyPointer<X509, X509_free_cpp> X509_Pointer;

CtoCpp1(EVP_PKEY_free, EVP_PKEY *)
typedef TidyPointer<EVP_PKEY, EVP_PKEY_free_cpp> EVP_PKEY_Pointer;

CtoCpp1(BN_free, BIGNUM *)
typedef TidyPointer<BIGNUM, BN_free_cpp> BIGNUM_Pointer;

CtoCpp1(BIO_free, BIO *)
typedef TidyPointer<BIO, BIO_free_cpp> BIO_Pointer;

CtoCpp1(ASN1_INTEGER_free, ASN1_INTEGER *)
typedef TidyPointer<ASN1_INTEGER, ASN1_INTEGER_free_cpp> ASN1_INT_Pointer;

CtoCpp1(TXT_DB_free, TXT_DB *)
typedef TidyPointer<TXT_DB, TXT_DB_free_cpp> TXT_DB_Pointer;

CtoCpp1(X509_NAME_free, X509_NAME *)
typedef TidyPointer<X509_NAME, X509_NAME_free_cpp> X509_NAME_Pointer;

CtoCpp1(RSA_free, RSA *)
typedef TidyPointer<RSA, RSA_free_cpp> RSA_Pointer;

CtoCpp1(X509_REQ_free, X509_REQ *)
typedef TidyPointer<X509_REQ, X509_REQ_free_cpp> X509_REQ_Pointer;

CtoCpp1(SSL_CTX_free, SSL_CTX *)
typedef TidyPointer<SSL_CTX, SSL_CTX_free_cpp> SSL_CTX_Pointer;

CtoCpp1(SSL_free, SSL *)
typedef TidyPointer<SSL, SSL_free_cpp> SSL_Pointer;


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
