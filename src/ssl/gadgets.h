/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_GADGETS_H
#define SQUID_SSL_GADGETS_H

#if USE_OPENSSL

#include "base/HardFun.h"
#include "compat/openssl.h"
#include "security/forward.h"
#include "ssl/crtd_message.h"

#include <string>

#if HAVE_OPENSSL_ASN1_H
#include <openssl/asn1.h>
#endif
#if HAVE_OPENSSL_TXT_DB_H
#include <openssl/txt_db.h>
#endif
#if HAVE_OPENSSL_X509V3_H
#include <openssl/x509v3.h>
#endif

namespace Ssl
{
/**
 \defgroup SslCrtdSslAPI SSL certificate generator API
 These functions must not depend on Squid runtime code such as debug()
 because they are used by security_file_certgen helper.
 */

#if !defined(SQUID_SSL_SIGN_HASH_IF_NONE)
#define SQUID_SSL_SIGN_HASH_IF_NONE "sha256"
#endif

/**
 * std::unique_ptr typedefs for common SSL objects
 */
sk_dtor_wrapper(sk_X509, STACK_OF(X509) *, X509_free);
typedef std::unique_ptr<STACK_OF(X509), sk_X509_free_wrapper> X509_STACK_Pointer;

typedef std::unique_ptr<BIGNUM, HardFun<void, BIGNUM*, &BN_free>> BIGNUM_Pointer;

typedef std::unique_ptr<BIO, HardFun<void, BIO*, &BIO_vfree>> BIO_Pointer;

typedef std::unique_ptr<ASN1_INTEGER, HardFun<void, ASN1_INTEGER*, &ASN1_INTEGER_free>> ASN1_INT_Pointer;

typedef std::unique_ptr<ASN1_OCTET_STRING, HardFun<void, ASN1_OCTET_STRING*, &ASN1_OCTET_STRING_free>> ASN1_OCTET_STRING_Pointer;

typedef std::unique_ptr<TXT_DB, HardFun<void, TXT_DB*, &TXT_DB_free>> TXT_DB_Pointer;

typedef std::unique_ptr<X509_NAME, HardFun<void, X509_NAME*, &X509_NAME_free>> X509_NAME_Pointer;

using EVP_PKEY_CTX_Pointer = std::unique_ptr<EVP_PKEY_CTX, HardFun<void, EVP_PKEY_CTX*, &EVP_PKEY_CTX_free>>;

typedef std::unique_ptr<X509_REQ, HardFun<void, X509_REQ*, &X509_REQ_free>> X509_REQ_Pointer;

typedef std::unique_ptr<AUTHORITY_KEYID, HardFun<void, AUTHORITY_KEYID*, &AUTHORITY_KEYID_free>> AUTHORITY_KEYID_Pointer;

sk_dtor_wrapper(sk_GENERAL_NAME, STACK_OF(GENERAL_NAME) *, GENERAL_NAME_free);
typedef std::unique_ptr<STACK_OF(GENERAL_NAME), sk_GENERAL_NAME_free_wrapper> GENERAL_NAME_STACK_Pointer;

typedef std::unique_ptr<GENERAL_NAME, HardFun<void, GENERAL_NAME*, &GENERAL_NAME_free>> GENERAL_NAME_Pointer;

typedef std::unique_ptr<X509_EXTENSION, HardFun<void, X509_EXTENSION*, &X509_EXTENSION_free>> X509_EXTENSION_Pointer;

typedef std::unique_ptr<X509_STORE_CTX, HardFun<void, X509_STORE_CTX *, &X509_STORE_CTX_free>> X509_STORE_CTX_Pointer;
/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to memory.
 */
bool writeCertAndPrivateKeyToMemory(Security::CertPointer const & cert, Security::PrivateKeyPointer const & pkey, std::string & bufferToWrite);

/**
 \ingroup SslCrtdSslAPI
 * Append SSL certificate to bufferToWrite.
 */
bool appendCertToMemory(Security::CertPointer const & cert, std::string & bufferToWrite);

/**
 \ingroup SslCrtdSslAPI
 * Write private key and SSL certificate to memory.
 */
bool readCertAndPrivateKeyFromMemory(Security::CertPointer & cert, Security::PrivateKeyPointer & pkey, char const * bufferToRead);

/**
 \ingroup SslCrtdSslAPI
 * Read SSL certificate from memory.
 */
bool readCertFromMemory(Security::CertPointer & cert, char const * bufferToRead);

/**
 \ingroup SslCrtdSslAPI
 * Read private key from file.
 */
void ReadPrivateKeyFromFile(char const * keyFilename, Security::PrivateKeyPointer &pkey, pem_password_cb *passwd_callback);

/**
 \ingroup SslCrtdSslAPI
 * Initialize the bio with the file 'filename' openned for reading
 */
bool OpenCertsFileForReading(BIO_Pointer &bio, const char *filename);

/// reads and returns a certificate using the given OpenSSL BIO
/// \returns a nil pointer on errors (TODO: throw instead)
Security::CertPointer ReadX509Certificate(const BIO_Pointer &);

/**
 \ingroup SslCrtdSslAPI
 * Read a private key from bio
 */
bool ReadPrivateKey(BIO_Pointer &bio, Security::PrivateKeyPointer &pkey, pem_password_cb *passwd_callback);

/**
 \ingroup SslCrtdSslAPI
 * Initialize the bio with the file 'filename' openned for writting
 */

bool OpenCertsFileForWriting(BIO_Pointer &bio, const char *filename);

/**
 \ingroup SslCrtdSslAPI
 * Write certificate to BIO.
 */
bool WriteX509Certificate(BIO_Pointer &bio, const Security::CertPointer & cert);

/**
 \ingroup SslCrtdSslAPI
 * Write private key to BIO.
 */
bool WritePrivateKey(BIO_Pointer &bio, const Security::PrivateKeyPointer &pkey);

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
    Security::PrivateKeyPointer signWithPkey; ///< The key of the signing certificate
    bool setValidAfter; ///< Do not mimic "Not Valid After" field
    bool setValidBefore; ///< Do not mimic "Not Valid Before" field
    bool setCommonName; ///< Replace the CN field of the mimicing subject with the given
    std::string commonName; ///< A CN to use for the generated certificate
    CertSignAlgorithm signAlgorithm; ///< The signing algorithm to use
    const EVP_MD *signHash; ///< The signing hash to use
private:
    CertificateProperties(CertificateProperties &);
    CertificateProperties &operator =(CertificateProperties const &);
};

/// \ingroup SslCrtdSslAPI
/// \returns certificate database key
std::string & OnDiskCertificateDbKey(const CertificateProperties &);

/**
 \ingroup SslCrtdSslAPI
 * Decide on the kind of certificate and generate a CA- or self-signed one.
 * The  generated certificate will inherite properties from certToMimic
 * Return generated certificate and private key in resultX509 and resultPkey
 * variables.
 */
bool generateSslCertificate(Security::CertPointer & cert, Security::PrivateKeyPointer & pkey, CertificateProperties const &properties);

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

/// \ingroup ServerProtocolSSLAPI
/// \return whether both certificates exist and are the same (e.g., have identical ASN.1 images)
bool CertificatesCmp(const Security::CertPointer &cert1, const Security::CertPointer &cert2);

/// wrapper for OpenSSL X509_get0_signature() which takes care of
/// portability issues with older OpenSSL versions
const ASN1_BIT_STRING *X509_get_signature(const Security::CertPointer &);

} // namespace Ssl

#endif // USE_OPENSSL
#endif // SQUID_SSL_GADGETS_H

