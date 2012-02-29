/*
 * $Id$
 */

#include "squid.h"
#include "ssl/gadgets.h"
#if HAVE_OPENSSL_X509V3_H
#include <openssl/x509v3.h>
#endif

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

// Replace certs common name with the given
static bool replaceCommonName(Ssl::X509_Pointer & cert, const char *cn)
{
    X509_NAME *name = X509_get_subject_name(cert.get());
    if (!name)
        return false;
    // Remove the CN part:
    int loc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (loc >=0) {
        X509_NAME_ENTRY *tmp = X509_NAME_get_entry(name, loc);
        X509_NAME_delete_entry(name, loc);
        X509_NAME_ENTRY_free(tmp);
    }

    // Add a new CN
    return X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
                                      (unsigned char *)cn, -1, -1, 0);
}

const char *Ssl::CertSignAlgorithmStr[] = {
    "signTrusted",
    "signUntrusted", 
    "signSelf",
    NULL
};

const char *Ssl::CertAdaptAlgorithmStr[] = {
    "setValidAfter",
    "setValidBefore",
    "setCommonName",
    NULL
};

Ssl::CertificateProperties::CertificateProperties():
                                                     setValidAfter(false),
                                                     setValidBefore(false),
                                                     setCommonName(false),
                                                     signAlgorithm(Ssl::algSignEnd)
{}

std::string & Ssl::CertificateProperties::dbKey() const
{
    static std::string certKey;
    certKey.clear();
    certKey.reserve(4096);
    if (mimicCert.get()) {
        char buf[1024];
        certKey.append(X509_NAME_oneline(X509_get_subject_name(mimicCert.get()), buf, sizeof(buf)));
    }

    if (certKey.empty()) {
        certKey.append("/CN=", 4);
        certKey.append(commonName);
    }

    if (setValidAfter)
        certKey.append("+SetValidAfter=on", 17);

    if (setValidBefore)
        certKey.append("+SetValidBefore=on", 18);

    if (setCommonName) {
        certKey.append("+SetCommonName=", 15);
        certKey.append(commonName);
    }

    if (signAlgorithm != Ssl::algSignEnd) {
        certKey.append("+Sign=", 6);
        certKey.append(certSignAlgorithm(signAlgorithm));
    }

    return certKey;
}

static bool buildCertificate(Ssl::X509_Pointer & cert, Ssl::CertificateProperties const &properties)
{ 
    // not an Ssl::X509_NAME_Pointer because X509_REQ_get_subject_name()
    // returns a pointer to the existing subject name. Nothing to clean here.
    if (properties.mimicCert.get()) {
        X509_NAME *name = X509_get_subject_name(properties.mimicCert.get());
        if (!name)
            return false;
        // X509_set_subject_name will call X509_dup for name 
        X509_set_subject_name(cert.get(), name);
    }

    if (properties.setCommonName || !properties.mimicCert.get()) {
        // In this case the CN of the certificate given by the user
        if (!replaceCommonName(cert, properties.commonName.c_str()))
            return false;
    }

    // We should get caCert notBefore and notAfter fields and do not allow 
    // notBefore/notAfter values from certToMimic before/after notBefore/notAfter
    // fields from caCert.
    // Currently there is not any way in openssl tollkit to compare two ASN1_TIME 
    // objects.
    ASN1_TIME *aTime = NULL;
    if (!properties.setValidBefore && properties.mimicCert.get())
        aTime = X509_get_notBefore(properties.mimicCert.get());
    if (!aTime && properties.signWithX509.get())
        aTime = X509_get_notBefore(properties.signWithX509.get());

    if (aTime) {
        if (!X509_set_notBefore(cert.get(), aTime))
            return false;
    }
    else if (!X509_gmtime_adj(X509_get_notBefore(cert.get()), (-2)*24*60*60))
        return false;

    aTime = NULL;
    if (!properties.setValidAfter && properties.mimicCert.get())
        aTime = X509_get_notAfter(properties.mimicCert.get());
    if (!aTime && properties.signWithX509.get())
        aTime = X509_get_notAfter(properties.signWithX509.get());
    if (aTime) {
        if (!X509_set_notAfter(cert.get(), aTime))
            return false;
    } else if (!X509_gmtime_adj(X509_get_notAfter(cert.get()), 60*60*24*356*3))
        return false;

    // mimic the alias and possibly subjectAltName
    if (properties.mimicCert.get()) {
        unsigned char *alStr;
        int alLen;
        alStr = X509_alias_get0(properties.mimicCert.get(), &alLen);
        if (alStr) {
            X509_alias_set1(cert.get(), alStr, alLen);
        }

        // Mimic subjectAltName unless we used a configured CN: browsers reject
        // certificates with CN unrelated to subjectAltNames.
        if (!properties.setCommonName) {
            int pos=X509_get_ext_by_NID (properties.mimicCert.get(), OBJ_sn2nid("subjectAltName"), -1);
            X509_EXTENSION *ext=X509_get_ext(properties.mimicCert.get(), pos); 
            if (ext)
                X509_add_ext(cert.get(), ext, -1);
        }
    }

    return true;
}

static bool generateFakeSslCertificate(Ssl::X509_Pointer & certToStore, Ssl::EVP_PKEY_Pointer & pkeyToStore, Ssl::CertificateProperties const &properties,  Ssl::BIGNUM_Pointer const &serial)
{
    Ssl::EVP_PKEY_Pointer pkey;
    // Use signing certificates private key as generated certificate private key
    if (properties.signWithPkey.get())
        pkey.resetAndLock(properties.signWithPkey.get());
    else // if not exist generate one
        pkey.reset(Ssl::createSslPrivateKey());

    if (!pkey)
        return false;

    Ssl::X509_Pointer cert(X509_new());
    if (!cert)
        return false;

    // Set pub key and serial given by the caller
    if (!X509_set_pubkey(cert.get(), pkey.get()))
        return false;
    if (!setSerialNumber(X509_get_serialNumber(cert.get()), serial.get()))
        return false;

    // Fill the certificate with the required properties
    if (!buildCertificate(cert, properties))
        return false;

    int ret = 0;
    // Set issuer name, from CA or our subject name for self signed cert
    if (properties.signAlgorithm != Ssl::algSignSelf && properties.signWithX509.get())
        ret = X509_set_issuer_name(cert.get(), X509_get_subject_name(properties.signWithX509.get()));
    else // Self signed certificate, set issuer to self
        ret = X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()));
    if (!ret)
        return false;

    /*Now sign the request */
    if (properties.signAlgorithm != Ssl::algSignSelf && properties.signWithPkey.get())
        ret = X509_sign(cert.get(), properties.signWithPkey.get(), EVP_sha1());
    else //else sign with self key (self signed request)
        ret = X509_sign(cert.get(), pkey.get(), EVP_sha1());

    if (!ret)
        return false;

    certToStore.reset(cert.release());
    pkeyToStore.reset(pkey.release());
    return true;
}

static  BIGNUM *createCertSerial(unsigned char *md, unsigned int n)
{
    
    assert(n == 20); //for sha1 n is 20 (for md5 n is 16)

    BIGNUM *serial = NULL;
    serial = BN_bin2bn(md, n, NULL);

    // if the serial is "0" set it to '1'
    if (BN_is_zero(serial))
        BN_one(serial);

    // serial size does not exceed 20 bytes
    assert(BN_num_bits(serial) <= 160);

    // According the RFC 5280, serial is an 20 bytes ASN.1 INTEGER (a signed big integer)
    // and the maximum value for X.509 certificate serial number is 2^159-1 and
    // the minimum 0. If the first bit of the serial is '1' ( eg 2^160-1),
    // will result to a negative integer.
    // To handle this, if the produced serial is greater than 2^159-1
    // truncate the last bit
    if (BN_is_bit_set(serial, 159))
        BN_clear_bit(serial, 159);

    return serial;
}

/// Return the SHA1 digest of the DER encoded version of the certificate
/// stored in a BIGNUM
static BIGNUM *x509Digest(Ssl::X509_Pointer const & cert)
{
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!X509_digest(cert.get(),EVP_sha1(),md,&n))
        return NULL;

    return createCertSerial(md, n);
}

static BIGNUM *x509Pubkeydigest(Ssl::X509_Pointer const & cert)
{
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!X509_pubkey_digest(cert.get(),EVP_sha1(),md,&n))
        return NULL;

    return createCertSerial(md, n);
}

/// Generate a unique serial number based on a Ssl::CertificateProperties object 
/// for a new generated certificate 
static bool createSerial(Ssl::BIGNUM_Pointer &serial, Ssl::CertificateProperties const &properties)
{
    Ssl::EVP_PKEY_Pointer fakePkey;
    Ssl::X509_Pointer fakeCert;

    serial.reset(x509Pubkeydigest(properties.signWithX509));
    if (!serial.get()) {
        serial.reset(BN_new());
        BN_is_zero(serial.get());
    }

    if (!generateFakeSslCertificate(fakeCert, fakePkey, properties, serial))
        return false;

    // The x509Fingerprint return an SHA1 hash.
    // both SHA1 hash and maximum serial number size are 20 bytes.
    BIGNUM *r = x509Digest(fakeCert);
    if (!r)
        return false;

    serial.reset(r);
    return true;
}

bool Ssl::generateSslCertificate(Ssl::X509_Pointer & certToStore, Ssl::EVP_PKEY_Pointer & pkeyToStore, Ssl::CertificateProperties const &properties)
{
    Ssl::BIGNUM_Pointer serial;

    if (!createSerial(serial, properties))
        return false;

    return  generateFakeSslCertificate(certToStore, pkeyToStore, properties, serial);
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

EVP_PKEY * Ssl::readSslPrivateKey(char const * keyFilename, pem_password_cb *passwd_callback)
{
    if (!keyFilename)
        return NULL;
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_file_internal()));
    if (!bio)
        return NULL;
    if (!BIO_read_filename(bio.get(), keyFilename))
        return NULL;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio.get(), NULL, passwd_callback, NULL);
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

bool Ssl::certificateMatchesProperties(X509 *cert, CertificateProperties const &properties)
{
    assert(cert);

    // For non self-signed certificates we have to check if the signing certificate changed
    if (properties.signAlgorithm != Ssl::algSignSelf) {
        if (X509_check_issued(properties.signWithX509.get(), cert) != X509_V_OK)
            return false;
    }
    
    X509 *cert2 = properties.mimicCert.get();
    // If there is not certificate to mimic stop here
    if (!cert2)
        return true;

    if (!properties.setCommonName) {
        X509_NAME *cert1_name = X509_get_subject_name(cert);
        X509_NAME *cert2_name = X509_get_subject_name(cert2);
        if (X509_NAME_cmp(cert1_name, cert2_name) != 0)
            return false;
    }
    /* else {
       if (properties.commonName != Ssl::CommonHostName(cert))
           return false;
       This function normaly called to verify a cached certificate matches the 
       specifications given by properties parameter.
       The cached certificate retrieved from the cache using a key which has
       as part the properties.commonName. This is enough to assume that the 
       cached cert has in its subject the properties.commonName as cn field.
       }
     */
 
    if (!properties.setValidBefore) {
        ASN1_TIME *aTime = X509_get_notBefore(cert);
        ASN1_TIME *bTime = X509_get_notBefore(cert2);
        if (asn1time_cmp(aTime, bTime) != 0)
            return false;
    }

    if (!properties.setValidAfter) {
        ASN1_TIME *aTime = X509_get_notAfter(cert);
        ASN1_TIME *bTime = X509_get_notAfter(cert2);
        if (asn1time_cmp(aTime, bTime) != 0)
            return false;
    }
    
    char *alStr1;
    int alLen;
    alStr1 = (char *)X509_alias_get0(cert, &alLen);
    char *alStr2  = (char *)X509_alias_get0(cert2, &alLen);
    if ((!alStr1 && alStr2) || (alStr1 && !alStr2) ||
        (alStr1 && alStr2 && strcmp(alStr1, alStr2)) != 0)
        return false;
    
    // Compare subjectAltName extension
    STACK_OF(GENERAL_NAME) * cert1_altnames;
    cert1_altnames = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
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
