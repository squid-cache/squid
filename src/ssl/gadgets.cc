/*
 * $Id$
 */

#include "config.h"
#include "ssl/gadgets.h"
#if HAVE_OPENSSL_X509V3_H
#include <openssl/x509v3.h>
#endif

/**
 \ingroup ServerProtocolSSLInternal
 * Add CN to subject in request.
 */
static bool addCnToRequest(Ssl::X509_REQ_Pointer & request, char const * cn)
{
    // not an Ssl::X509_NAME_Pointer because X509_REQ_get_subject_name()
    // returns a pointer to the existing subject name. Nothing to clean here.
    X509_NAME *name = X509_REQ_get_subject_name(request.get());
    if (!name)
        return false;

    // The second argument of the X509_NAME_add_entry_by_txt declared as
    // "char *" on some OS. Use cn_name to avoid compile warnings.
    static char cn_name[3] = "CN";
    if (!X509_NAME_add_entry_by_txt(name, cn_name, MBSTRING_ASC, (unsigned char *)cn, -1, -1, 0))
        return false;

    return true;
}

/**
 \ingroup ServerProtocolSSLInternal
 * Make request on sign using private key and hostname.
 */
static bool makeRequest(Ssl::X509_REQ_Pointer & request, Ssl::EVP_PKEY_Pointer const & pkey, char const * host)
{
    if (!X509_REQ_set_version(request.get(), 0L))
        return false;

    if (!addCnToRequest(request, host))
        return false;

    if (!X509_REQ_set_pubkey(request.get(), pkey.get()))
        return false;
    return true;
}

EVP_PKEY * Ssl::createSslPrivateKey()
{
    Ssl::EVP_PKEY_Pointer pkey(EVP_PKEY_new());

    if (!pkey)
        return NULL;

    Ssl::RSA_Pointer rsa(RSA_generate_key(1024, RSA_F4, NULL, NULL));

    if (!rsa)
        return NULL;

    if (!EVP_PKEY_assign_RSA(pkey.get(), (rsa.get())))
        return NULL;

    rsa.release();
    return pkey.release();
}

X509_REQ * Ssl::createNewX509Request(Ssl::EVP_PKEY_Pointer const & pkey, const char * hostname)
{
    Ssl::X509_REQ_Pointer request(X509_REQ_new());

    if (!request)
        return NULL;

    if (!makeRequest(request, pkey, hostname))
        return NULL;
    return request.release();
}

/**
 \ingroup ServerProtocolSSLInternal
 * Set serial random serial number or set random serial number.
 */
static bool setSerialNumber(ASN1_INTEGER *ai, BIGNUM const* serial)
{
    if (!ai)
        return false;
    Ssl::BIGNUM_Pointer bn(BN_new());
    if (serial) {
        bn.reset(BN_dup(serial));
    } else {
        if (!bn)
            return false;

        if (!BN_pseudo_rand(bn.get(), 64, 0, 0))
            return false;
    }

    if (ai && !BN_to_ASN1_INTEGER(bn.get(), ai))
        return false;
    return true;
}

X509 * Ssl::signRequest(Ssl::X509_REQ_Pointer const & request, Ssl::X509_Pointer const & x509, Ssl::EVP_PKEY_Pointer const & pkey, ASN1_TIME * timeNotAfter, BIGNUM const * serial)
{
    Ssl::X509_Pointer cert(X509_new());
    if (!cert)
        return NULL;

    if (!setSerialNumber(X509_get_serialNumber(cert.get()), serial))
        return NULL;

    if (!X509_set_issuer_name(cert.get(), x509.get() ? X509_get_subject_name(x509.get()) : X509_REQ_get_subject_name(request.get())))
        return NULL;

    if (!X509_gmtime_adj(X509_get_notBefore(cert.get()), (-2)*24*60*60))
        return NULL;

    if (timeNotAfter) {
        if (!X509_set_notAfter(cert.get(), timeNotAfter))
            return NULL;
    } else if (!X509_gmtime_adj(X509_get_notAfter(cert.get()), 60*60*24*356*3))
        return NULL;

    if (!X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(request.get())))
        return NULL;

    Ssl::EVP_PKEY_Pointer tmppkey(X509_REQ_get_pubkey(request.get()));

    if (!tmppkey || !X509_set_pubkey(cert.get(), tmppkey.get()))
        return NULL;

    if (!X509_sign(cert.get(), pkey.get(), EVP_sha1()))
        return NULL;

    return cert.release();
}

bool Ssl::writeCertAndPrivateKeyToMemory(Ssl::X509_Pointer const & cert, Ssl::EVP_PKEY_Pointer const & pkey, std::string & bufferToWrite)
{
    bufferToWrite.clear();
    if (!pkey || !cert)
        return false;
    BIO_Pointer bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return false;

    if (!PEM_write_bio_X509 (bio.get(), cert.get()))
        return false;

    if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), NULL, NULL, 0, NULL, NULL))
        return false;

    char *ptr = NULL;
    long len = BIO_get_mem_data(bio.get(), &ptr);
    if (!ptr)
        return false;

    bufferToWrite = std::string(ptr, len);
    return true;
}

bool Ssl::appendCertToMemory(Ssl::X509_Pointer const & cert, std::string & bufferToWrite)
{
    if (!cert)
        return false;

    BIO_Pointer bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return false;

    if (!PEM_write_bio_X509 (bio.get(), cert.get()))
        return false;

    char *ptr = NULL;
    long len = BIO_get_mem_data(bio.get(), &ptr);
    if (!ptr)
        return false;

    if (!bufferToWrite.empty()) 
        bufferToWrite.append(" "); // add a space...

    bufferToWrite.append(ptr, len);
    return true;
}

bool Ssl::writeCertAndPrivateKeyToFile(Ssl::X509_Pointer const & cert, Ssl::EVP_PKEY_Pointer const & pkey, char const * filename)
{
    if (!pkey || !cert)
        return false;

    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file_internal()));
    if (!bio)
        return false;
    if (!BIO_write_filename(bio.get(), const_cast<char *>(filename)))
        return false;

    if (!PEM_write_bio_X509(bio.get(), cert.get()))
        return false;

    if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), NULL, NULL, 0, NULL, NULL))
        return false;

    return true;
}

bool Ssl::readCertAndPrivateKeyFromMemory(Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey, char const * bufferToRead)
{
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
    BIO_puts(bio.get(), bufferToRead);

    X509 * certPtr = NULL;
    cert.reset(PEM_read_bio_X509(bio.get(), &certPtr, 0, 0));
    if (!cert)
        return false;

    EVP_PKEY * pkeyPtr = NULL;
    pkey.reset(PEM_read_bio_PrivateKey(bio.get(), &pkeyPtr, 0, 0));
    if (!pkey)
        return false;

    return true;
}

bool Ssl::readCertFromMemory(X509_Pointer & cert, char const * bufferToRead)
{
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
    BIO_puts(bio.get(), bufferToRead);

    X509 * certPtr = NULL;
    cert.reset(PEM_read_bio_X509(bio.get(), &certPtr, 0, 0));
    if (!cert)
        return false;

    return true;
}

bool Ssl::generateSslCertificateAndPrivateKey(char const *host, Ssl::X509_Pointer const & signedX509, Ssl::EVP_PKEY_Pointer const & signedPkey, Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey, BIGNUM const * serial)
{
    pkey.reset(createSslPrivateKey());
    if (!pkey)
        return false;

    Ssl::X509_REQ_Pointer request(createNewX509Request(pkey, host));
    if (!request)
        return false;

    if (signedX509.get() && signedPkey.get())
        cert.reset(signRequest(request, signedX509, signedPkey, X509_get_notAfter(signedX509.get()), serial));
    else
        cert.reset(signRequest(request, signedX509, pkey, NULL, serial));

    if (!cert)
        return false;

    return true;
}

static bool mimicCertificate(Ssl::X509_Pointer & cert, Ssl::X509_Pointer const & caCert, Ssl::X509_Pointer const &certToMimic)
{ 
    // not an Ssl::X509_NAME_Pointer because X509_REQ_get_subject_name()
    // returns a pointer to the existing subject name. Nothing to clean here.
    X509_NAME *name = X509_get_subject_name(certToMimic.get());
    if (!name)
        return false;
    // X509_set_subject_name will call X509_dup for name 
    X509_set_subject_name(cert.get(), name);


    // We should get caCert notBefore and notAfter fields and do not allow 
    // notBefore/notAfter values from certToMimic before/after notBefore/notAfter
    // fields from caCert.
    // Currently there is not any way in openssl tollkit to compare two ASN1_TIME 
    // objects.
    ASN1_TIME *aTime;
    if ((aTime = X509_get_notBefore(certToMimic.get())) || (aTime = X509_get_notBefore(caCert.get())) ) {
        if (!X509_set_notBefore(cert.get(), aTime))
            return false;
    }
    else if (!X509_gmtime_adj(X509_get_notBefore(cert.get()), (-2)*24*60*60))
        return false;

    if ((aTime = X509_get_notAfter(certToMimic.get())) || (aTime = X509_get_notAfter(caCert.get())) ) {
        if (!X509_set_notAfter(cert.get(), aTime))
            return NULL;
    } else if (!X509_gmtime_adj(X509_get_notAfter(cert.get()), 60*60*24*356*3))
        return NULL;

    
    unsigned char *alStr;
    int alLen;
    alStr = X509_alias_get0(certToMimic.get(), &alLen);
    if (alStr) {
        X509_alias_set1(cert.get(), alStr, alLen);
    }

    // Add subjectAltName extension used to support multiple hostnames with one certificate
    int pos=X509_get_ext_by_NID (certToMimic.get(), OBJ_sn2nid("subjectAltName"), -1);
    X509_EXTENSION *ext=X509_get_ext(certToMimic.get(), pos); 
    if (ext)
        X509_add_ext(cert.get(), ext, -1);

    return true;
}

bool Ssl::generateSslCertificate(Ssl::X509_Pointer const &certToMimic, Ssl::X509_Pointer const & signedX509, Ssl::EVP_PKEY_Pointer const & signedPkey, Ssl::X509_Pointer & certToStore, Ssl::EVP_PKEY_Pointer & pkey, BIGNUM const * serial)
{
    if (!certToMimic.get())
        return false;

    pkey.reset(createSslPrivateKey());
    if (!pkey)
        return false;

    Ssl::X509_Pointer cert(X509_new());
    if (!cert)
        return false;

    // Set pub key and serial given by the caller
    if (!X509_set_pubkey(cert.get(), pkey.get()))
        return false;
    if (!setSerialNumber(X509_get_serialNumber(cert.get()), serial))
        return false;

    // inherit properties from certToMimic
    if (!mimicCertificate(cert, signedX509, certToMimic))
        return false;

    // Set issuer name, from CA or our subject name for self signed cert
    if (!X509_set_issuer_name(cert.get(), signedX509.get() ? X509_get_subject_name(signedX509.get()) : X509_get_subject_name(cert.get())))
        return false;

    /*Now sign the request */
    int ret = 0;
    if (signedPkey.get())
        ret = X509_sign(cert.get(), signedPkey.get(), EVP_sha1());
    else //else sign with self key (self signed request)
        ret = X509_sign(cert.get(), pkey.get(), EVP_sha1());

    if (!ret)
        return false;

    certToStore.reset(cert.release());
    return true;
}

/**
 \ingroup ServerProtocolSSLInternal
 * Read certificate from file.
 */
static X509 * readSslX509Certificate(char const * certFilename)
{
    if (!certFilename)
        return NULL;
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file_internal()));
    if (!bio)
        return NULL;
    if (!BIO_read_filename(bio.get(), certFilename))
        return NULL;
    X509 *certificate = PEM_read_bio_X509(bio.get(), NULL, NULL, NULL);
    return certificate;
}

EVP_PKEY * Ssl::readSslPrivateKey(char const * keyFilename)
{
    if (!keyFilename)
        return NULL;
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file_internal()));
    if (!bio)
        return NULL;
    if (!BIO_read_filename(bio.get(), keyFilename))
        return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL);
    return pkey;
}

void Ssl::readCertAndPrivateKeyFromFiles(Ssl::X509_Pointer & cert, Ssl::EVP_PKEY_Pointer & pkey, char const * certFilename, char const * keyFilename)
{
    if (keyFilename == NULL)
        keyFilename = certFilename;
    pkey.reset(readSslPrivateKey(keyFilename));
    cert.reset(readSslX509Certificate(certFilename));
    if (!pkey || !cert || !X509_check_private_key(cert.get(), pkey.get())) {
        pkey.reset(NULL);
        cert.reset(NULL);
    }
}

bool Ssl::sslDateIsInTheFuture(char const * date)
{
    ASN1_UTCTIME tm;
    tm.flags = 0;
    tm.type = 23;
    tm.data = (unsigned char *)date;
    tm.length = strlen(date);

    return (X509_cmp_current_time(&tm) > 0);
}

/// Print the time represented by a ASN1_TIME struct to a string using GeneralizedTime format
static bool asn1timeToGeneralizedTimeStr(ASN1_TIME *aTime, char *buf, int bufLen)
{
    // ASN1_Time  holds time to UTCTime or GeneralizedTime form. 
    // UTCTime has the form YYMMDDHHMMSS[Z | [+|-]offset]
    // GeneralizedTime has the form YYYYMMDDHHMMSS[Z | [+|-] offset]

    // length should have space for data plus 2 extra bytes for the two extra year fields
    // plus the '\0' char.
    if ((aTime->length + 3) > bufLen)
        return false;

    char *str;
    if (aTime->type == V_ASN1_UTCTIME) {
        if (aTime->data[0] > '5') { // RFC 2459, section 4.1.2.5.1
            buf[0] = '1';
            buf[1] = '9';
        } else {
            buf[0] = '2';
            buf[1] = '0';
        }
        str = buf +2;
    }
    else // if (aTime->type == V_ASN1_GENERALIZEDTIME)
        str = buf;

    memcpy(str, aTime->data, aTime->length);
    str[aTime->length] = '\0';
    return true;
}

static int asn1time_cmp(ASN1_TIME *asnTime1, ASN1_TIME *asnTime2)
{
    char strTime1[64], strTime2[64];
    if (!asn1timeToGeneralizedTimeStr(asnTime1, strTime1, sizeof(strTime1)))
        return -1;
    if (!asn1timeToGeneralizedTimeStr(asnTime2, strTime2, sizeof(strTime2)))
        return -1;
    
    return strcmp(strTime1, strTime2);
}

bool Ssl::ssl_match_certificates(X509 *cert1, X509 *cert2)
{
    assert(cert1 && cert2);
    X509_NAME *cert1_name = X509_get_subject_name(cert1);
    X509_NAME *cert2_name = X509_get_subject_name(cert2);
    if (X509_NAME_cmp(cert1_name, cert2_name) != 0)
        return false;
 
    ASN1_TIME *aTime = X509_get_notBefore(cert1);
    ASN1_TIME *bTime = X509_get_notBefore(cert2);
    if (asn1time_cmp(aTime, bTime) != 0)
        return false;

    aTime = X509_get_notAfter(cert1);
    bTime = X509_get_notAfter(cert2);
    if (asn1time_cmp(aTime, bTime) != 0)
        return false;
    
    char *alStr1;
    int alLen;
    alStr1 = (char *)X509_alias_get0(cert1, &alLen);
    char *alStr2  = (char *)X509_alias_get0(cert2, &alLen);
    if ((!alStr1 && alStr2) || (alStr1 && !alStr2) ||
        (alStr1 && alStr2 && strcmp(alStr1, alStr2)) != 0)
        return false;
    
    // Compare subjectAltName extension
    STACK_OF(GENERAL_NAME) * cert1_altnames;
    cert1_altnames = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert1, NID_subject_alt_name, NULL, NULL);
    STACK_OF(GENERAL_NAME) * cert2_altnames;
    cert2_altnames = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert2, NID_subject_alt_name, NULL, NULL);
    bool match = true;
    if (cert1_altnames) {
        int numalts = sk_GENERAL_NAME_num(cert1_altnames);
        for (int i = 0; match && i < numalts; i++) {
            const GENERAL_NAME *aName = sk_GENERAL_NAME_value(cert1_altnames, i);
            match = sk_GENERAL_NAME_find(cert2_altnames, aName);
        }
    }
    else if (cert2_altnames)
        match = false;
 
    sk_GENERAL_NAME_pop_free(cert1_altnames, GENERAL_NAME_free);
    sk_GENERAL_NAME_pop_free(cert2_altnames, GENERAL_NAME_free);

    return match;
}
