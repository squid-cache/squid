/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_GADGETS_H
#define SQUID_SSL_GADGETS_H

#include "security/forward.h"
#include "ssl/crtd_message.h"

#if HAVE_OPENSSL_TXT_DB_H
#include <openssl/txt_db.h>
#endif
#include <string>

namespace Ssl
{
/**
 \defgroup SslCrtdSslAPI ssl_crtd SSL api.
 These functions must not depend on Squid runtime code such as debug()
 because they are used by ssl_crtd.
 */

#if SQUID_USE_CONST_SSL_METHOD
typedef const SSL_METHOD * ContextMethod;
#else
typedef SSL_METHOD * ContextMethod;
#endif

#if !defined(SQUID_SSL_SIGN_HASH_IF_NONE)
#define SQUID_SSL_SIGN_HASH_IF_NONE "sha256"
#endif

/**
 \ingroup SslCrtdSslAPI
 * TidyPointer typedefs for  common SSL objects
 */
sk_free_wrapper(sk_X509, STACK_OF(X509) *, X509_free)
typedef TidyPointer<STACK_OF(X509), sk_X509_free_wrapper> X509_STACK_Pointer;

CtoCpp1(EVP_PKEY_free, EVP_PKEY *)
typedef Security::LockingPointer<EVP_PKEY, EVP_PKEY_free_cpp, CRYPTO_LOCK_EVP_PKEY> EVP_PKEY_Pointer;

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

sk_free_wrapper(sk_X509_NAME, STACK_OF(X509_NAME) *, X509_NAME_free)
typedef TidyPointer<STACK_OF(X509_NAME), sk_X509_NAME_free_wrapper> X509_NAME_STACK_Pointer;

/**
 \ingroup SslCrtdSslAPI
 * Create 1024 bits rsa key.
 */
EVP_PKEY * createSslPrivateKey();

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to memory.
 */
bool writeCertAndPrivateKeyToMemory(Security::CertPointer const & cert, EVP_PKEY_Pointer const & pkey, std::string & bufferToWrite);

/**
 \ingroup SslCrtdSslAPI
 * Append SSL certificate to bufferToWrite.
 */
bool appendCertToMemory(Security::CertPointer const & cert, std::string & bufferToWrite);

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to file.
 */
bool writeCertAndPrivateKeyToFile(Security::CertPointer const & cert, EVP_PKEY_Pointer const & pkey, char const * filename);

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to memory.
 */
bool readCertAndPrivateKeyFromMemory(Security::CertPointer & cert, EVP_PKEY_Pointer & pkey, char const * bufferToRead);

/**
 \ingroup SslCrtdSslAPI
 * Read SSL certificate from memory.
 */
bool readCertFromMemory(Security::CertPointer & cert, char const * bufferToRead);

/**
  \ingroup SslCrtdSslAPI
 * Supported certificate signing algorithms
 */
enum CertSignAlgorithm {algSignTrusted = 0, algSignUntrusted, algSignSelf, algSignEnd};

/**
 \ingroup SslCrtdSslAPI
 * Short names for certificate signing algorithms
 */

extern const char *CertSignAlgorithmStr[];

/**
 \ingroup SslCrtdSslAPI
 * Return the short name of the signing algorithm "sg"
 */
inline const char *certSignAlgorithm(int sg)
{
    if (sg >=0 && sg < Ssl::algSignEnd)
        return Ssl::CertSignAlgorithmStr[sg];

    return NULL;
}

/**
 \ingroup SslCrtdSslAPI
 * Return the id of the signing algorithm "sg"
 */
inline CertSignAlgorithm certSignAlgorithmId(const char *sg)
{
    for (int i = 0; i < algSignEnd && Ssl::CertSignAlgorithmStr[i] != NULL; i++)
        if (strcmp(Ssl::CertSignAlgorithmStr[i], sg) == 0)
            return (CertSignAlgorithm)i;

    return algSignEnd;
}

/**
 \ingroup SslCrtdSslAPI
 * Supported certificate adaptation algorithms
 */
enum CertAdaptAlgorithm {algSetValidAfter = 0, algSetValidBefore, algSetCommonName, algSetEnd};

/**
 \ingroup SslCrtdSslAPI
 * Short names for certificate adaptation algorithms
 */
extern const char *CertAdaptAlgorithmStr[];

/**
 \ingroup SslCrtdSslAPI
 * Return the short name of the adaptation algorithm "alg"
 */
inline const char *sslCertAdaptAlgoritm(int alg)
{
    if (alg >=0 && alg < Ssl::algSetEnd)
        return Ssl::CertAdaptAlgorithmStr[alg];

    return NULL;
}

/**
 \ingroup SslCrtdSslAPI
 * Simple struct to pass certificate generation parameters to generateSslCertificate function.
 */
class CertificateProperties
{
public:
    CertificateProperties();
    Security::CertPointer mimicCert; ///< Certificate to mimic
    Security::CertPointer signWithX509; ///< Certificate to sign the generated request
    EVP_PKEY_Pointer signWithPkey; ///< The key of the signing certificate
    bool setValidAfter; ///< Do not mimic "Not Valid After" field
    bool setValidBefore; ///< Do not mimic "Not Valid Before" field
    bool setCommonName; ///< Replace the CN field of the mimicing subject with the given
    std::string commonName; ///< A CN to use for the generated certificate
    CertSignAlgorithm signAlgorithm; ///< The signing algorithm to use
    const EVP_MD *signHash; ///< The signing hash to use
    /// Returns certificate database primary key. New fake certificates
    /// purge old fake certificates with the same key.
    std::string & dbKey() const;
private:
    CertificateProperties(CertificateProperties &);
    CertificateProperties &operator =(CertificateProperties const &);
};

/**
 \ingroup SslCrtdSslAPI
 * Decide on the kind of certificate and generate a CA- or self-signed one.
 * The  generated certificate will inherite properties from certToMimic
 * Return generated certificate and private key in resultX509 and resultPkey
 * variables.
 */
bool generateSslCertificate(Security::CertPointer & cert, EVP_PKEY_Pointer & pkey, CertificateProperties const &properties);

/**
 \ingroup SslCrtdSslAPI
 * Read private key from file. Make sure that this is not encrypted file.
 */
EVP_PKEY * readSslPrivateKey(char const * keyFilename, pem_password_cb *passwd_callback = NULL);

/**
 \ingroup SslCrtdSslAPI
 *  Read certificate and private key from files.
 * \param certFilename name of file with certificate.
 * \param keyFilename name of file with private key.
 */
void readCertAndPrivateKeyFromFiles(Security::CertPointer & cert, EVP_PKEY_Pointer & pkey, char const * certFilename, char const * keyFilename);

/**
 \ingroup SslCrtdSslAPI
 * Verify date. Date format it ASN1_UTCTIME. if there is out of date error,
 * return false.
*/
bool sslDateIsInTheFuture(char const * date);

/**
 \ingroup SslCrtdSslAPI
 * Check if the major fields of a certificates matches the properties given by
 * a CertficateProperties object
 \return true if the certificates matches false otherwise.
*/
bool certificateMatchesProperties(X509 *peer_cert, CertificateProperties const &properties);

/**
   \ingroup ServerProtocolSSLAPI
   * Returns CN from the certificate, suitable for use as a host name.
   * Uses static memory to temporary store the extracted name.
*/
const char *CommonHostName(X509 *x509);

/**
   \ingroup ServerProtocolSSLAPI
   * Returns Organization from the certificate.
   * Uses static memory to temporary store the extracted name.
*/
const char *getOrganization(X509 *x509);

} // namespace Ssl
#endif // SQUID_SSL_GADGETS_H

