/*
 * $Id$
 */

#include "config.h"
#include "ssl/gadgets.h"

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

/**
 \ingroup ServerProtocolSSLInternal
 * Read private key from file. Make sure that this is not encrypted file.
 */
static EVP_PKEY * readSslPrivateKey(char const * keyFilename)
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
