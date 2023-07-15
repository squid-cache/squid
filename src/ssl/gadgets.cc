/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/IoManip.h"
#include "error/SysErrorDetail.h"
#include "sbuf/Stream.h"
#include "security/Io.h"
#include "ssl/gadgets.h"

void
Ssl::ForgetErrors()
{
    if (ERR_peek_last_error()) {
        debugs(83, 5, "forgetting stale OpenSSL errors:" << ReportAndForgetErrors);
        // forget errors if section/level-specific debugging above was disabled
        while (ERR_get_error()) {}
    }

    // Technically, the caller should just ignore (potentially stale) errno when
    // no system calls have failed. However, due to OpenSSL error-reporting API
    // deficiencies, many callers cannot detect when a TLS error was caused by a
    // system call failure. We forget the stale errno (just like we forget stale
    // OpenSSL errors above) so that the caller only uses fresh errno values.
    errno = 0;
}

std::ostream &
Ssl::ReportAndForgetErrors(std::ostream &os)
{
    unsigned int reported = 0; // efficiently marks ForgetErrors() call boundary
    while (const auto errorToForget = ERR_get_error())
        os << Debug::Extra << "OpenSSL-saved error #" << (++reported) << ": " << asHex(errorToForget);
    return os;
}

[[ noreturn ]] static void
ThrowErrors(const char * const problem, const int savedErrno, const SourceLocation &where)
{
    throw TextException(ToSBuf(problem, ": ",
                               Ssl::ReportAndForgetErrors,
                               ReportSysError(savedErrno)),
                        where);
}

static Security::PrivateKeyPointer
CreateRsaPrivateKey()
{
    Ssl::EVP_PKEY_CTX_Pointer rsa(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!rsa)
        return nullptr;

    if (EVP_PKEY_keygen_init(rsa.get()) <= 0)
        return nullptr;

    int num = 2048; // Maybe use 4096 RSA keys, or better make it configurable?
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(rsa.get(), num) <= 0)
        return nullptr;

    /* Generate key */
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(rsa.get(), &pkey) <= 0)
        return nullptr;

    return Security::PrivateKeyPointer(pkey);
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

        if (!BN_rand(bn.get(), 64, 0, 0))
            return false;
    }

    if (ai && !BN_to_ASN1_INTEGER(bn.get(), ai))
        return false;
    return true;
}

bool Ssl::writeCertAndPrivateKeyToMemory(Security::CertPointer const & cert, Security::PrivateKeyPointer const & pkey, std::string & bufferToWrite)
{
    bufferToWrite.clear();
    if (!pkey || !cert)
        return false;
    BIO_Pointer bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return false;

    if (!PEM_write_bio_X509 (bio.get(), cert.get()))
        return false;

    if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr))
        return false;

    char *ptr = nullptr;
    long len = BIO_get_mem_data(bio.get(), &ptr);
    if (!ptr)
        return false;

    bufferToWrite = std::string(ptr, len);
    return true;
}

bool Ssl::appendCertToMemory(Security::CertPointer const & cert, std::string & bufferToWrite)
{
    if (!cert)
        return false;

    BIO_Pointer bio(BIO_new(BIO_s_mem()));
    if (!bio)
        return false;

    if (!PEM_write_bio_X509 (bio.get(), cert.get()))
        return false;

    char *ptr = nullptr;
    long len = BIO_get_mem_data(bio.get(), &ptr);
    if (!ptr)
        return false;

    if (!bufferToWrite.empty())
        bufferToWrite.append(" "); // add a space...

    bufferToWrite.append(ptr, len);
    return true;
}

bool Ssl::readCertAndPrivateKeyFromMemory(Security::CertPointer & cert, Security::PrivateKeyPointer & pkey, char const * bufferToRead)
{
    Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
    BIO_puts(bio.get(), bufferToRead);

    try {
        cert = ReadCertificate(bio);
    } catch (...) {
        debugs(83, DBG_IMPORTANT, "ERROR: Cannot deserialize a signing certificate:" <<
               Debug::Extra << "problem: " << CurrentException);
        cert.reset();
        pkey.reset();
        return false;
    }

    EVP_PKEY * pkeyPtr = nullptr;
    pkey.resetWithoutLocking(PEM_read_bio_PrivateKey(bio.get(), &pkeyPtr, nullptr, nullptr));
    if (!pkey)
        return false;

    return true;
}

// TODO: Convert matching BIO_s_mem() callers.
Ssl::BIO_Pointer
Ssl::ReadOnlyBioTiedTo(const char * const bufferToRead)
{
    ForgetErrors();
    // OpenSSL BIO API is not const-correct, but OpenSSL does not free or modify
    // BIO_new_mem_buf() data because it is marked with BIO_FLAGS_MEM_RDONLY.
    const auto castedBuffer = const_cast<char*>(bufferToRead);
    if (const auto bio = BIO_new_mem_buf(castedBuffer, -1)) // no memcpy()
        return BIO_Pointer(bio);
    const auto savedErrno = errno;
    ThrowErrors("cannot allocate OpenSSL BIO structure", savedErrno, Here());
}

// According to RFC 5280 (Section A.1), the common name length in a certificate
// can be at most 64 characters
static const size_t MaxCnLen = 64;

// Replace certs common name with the given
static bool replaceCommonName(Security::CertPointer & cert, std::string const &rawCn)
{
    std::string cn = rawCn;

    if (cn.length() > MaxCnLen) {
        // In the case the length of CN is more than the maximum supported size
        // try to use the first upper level domain.
        size_t pos = 0;
        do {
            pos = cn.find('.', pos + 1);
        } while (pos != std::string::npos && (cn.length() - pos + 2) > MaxCnLen);

        // If no short domain found or this domain is a toplevel domain
        // we failed to find a good cn name.
        if (pos == std::string::npos || cn.find('.', pos + 1) == std::string::npos)
            return false;

        std::string fixedCn(1, '*');
        fixedCn.append(cn.c_str() + pos);
        cn = fixedCn;
    }

    // Assume [] surround an IPv6 address and strip them because browsers such
    // as Firefox, Chromium, and Safari prefer bare IPv6 addresses in CNs.
    if (cn.length() > 2 && *cn.begin() == '[' && *cn.rbegin() == ']')
        cn = cn.substr(1, cn.size()-2);

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
                                      (unsigned char *)(cn.c_str()), -1, -1, 0);
}

const char *Ssl::CertSignAlgorithmStr[] = {
    "signTrusted",
    "signUntrusted",
    "signSelf",
    nullptr
};

const char *Ssl::CertAdaptAlgorithmStr[] = {
    "setValidAfter",
    "setValidBefore",
    "setCommonName",
    nullptr
};

Ssl::CertificateProperties::CertificateProperties():
    setValidAfter(false),
    setValidBefore(false),
    setCommonName(false),
    signAlgorithm(Ssl::algSignEnd),
    signHash(nullptr)
{}

static void
printX509Signature(const Security::CertPointer &cert, std::string &out)
{
    const ASN1_BIT_STRING *sig = Ssl::X509_get_signature(cert);
    if (sig && sig->data) {
        const unsigned char *s = sig->data;
        for (int i = 0; i < sig->length; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", s[i]);
            out.append(hex);
        }
    }
}

std::string &
Ssl::OnDiskCertificateDbKey(const Ssl::CertificateProperties &properties)
{
    static std::string certKey;
    certKey.clear();
    certKey.reserve(4096);
    if (properties.mimicCert.get())
        printX509Signature(properties.mimicCert, certKey);

    if (certKey.empty()) {
        certKey.append("/CN=", 4);
        certKey.append(properties.commonName);
    }

    if (properties.setValidAfter)
        certKey.append("+SetValidAfter=on", 17);

    if (properties.setValidBefore)
        certKey.append("+SetValidBefore=on", 18);

    if (properties.setCommonName) {
        certKey.append("+SetCommonName=", 15);
        certKey.append(properties.commonName);
    }

    if (properties.signAlgorithm != Ssl::algSignEnd) {
        certKey.append("+Sign=", 6);
        certKey.append(certSignAlgorithm(properties.signAlgorithm));
    }

    if (properties.signHash != nullptr) {
        certKey.append("+SignHash=", 10);
        certKey.append(EVP_MD_name(properties.signHash));
    }

    return certKey;
}

/// Check if mimicCert certificate has the Authority Key Identifier extension
/// and if yes add the extension to cert certificate with the same fields if
/// possible. If the issuerCert certificate  does not have the Subject Key
/// Identifier extension (required to build the keyIdentifier field of
/// AuthorityKeyIdentifier) then the authorityCertIssuer and
/// authorityCertSerialNumber fields added.
static bool
mimicAuthorityKeyId(Security::CertPointer &cert, Security::CertPointer const &mimicCert, Security::CertPointer const &issuerCert)
{
    if (!mimicCert.get() || !issuerCert.get())
        return false;

    Ssl::AUTHORITY_KEYID_Pointer akid((AUTHORITY_KEYID *)X509_get_ext_d2i(mimicCert.get(), NID_authority_key_identifier, nullptr, nullptr));

    bool addKeyId = false, addIssuer = false;
    if (akid.get()) {
        addKeyId = (akid.get()->keyid != nullptr);
        addIssuer = (akid.get()->issuer && akid.get()->serial);
    }

    if (!addKeyId && !addIssuer)
        return false; // No need to add AuthorityKeyIdentifier

    Ssl::ASN1_OCTET_STRING_Pointer issuerKeyId;
    if (addKeyId) {
        X509_EXTENSION *ext;
        // Check if the issuer has the Subject Key Identifier extension
        const int indx = X509_get_ext_by_NID(issuerCert.get(), NID_subject_key_identifier, -1);
        if (indx >= 0 && (ext = X509_get_ext(issuerCert.get(), indx))) {
            issuerKeyId.reset((ASN1_OCTET_STRING *)X509V3_EXT_d2i(ext));
        }
    }

    Ssl::X509_NAME_Pointer issuerName;
    Ssl::ASN1_INT_Pointer issuerSerial;
    if (issuerKeyId.get() == nullptr || addIssuer) {
        issuerName.reset(X509_NAME_dup(X509_get_issuer_name(issuerCert.get())));
        issuerSerial.reset(ASN1_INTEGER_dup(X509_get_serialNumber(issuerCert.get())));
    }

    Ssl::AUTHORITY_KEYID_Pointer theAuthKeyId(AUTHORITY_KEYID_new());
    if (!theAuthKeyId.get())
        return false;
    theAuthKeyId.get()->keyid = issuerKeyId.release();
    if (issuerName && issuerSerial) {
        Ssl::GENERAL_NAME_STACK_Pointer genNames(sk_GENERAL_NAME_new_null());
        if (genNames.get()) {
            if (GENERAL_NAME *aname = GENERAL_NAME_new()) {
                sk_GENERAL_NAME_push(genNames.get(), aname);
                aname->type = GEN_DIRNAME;
                aname->d.dirn = issuerName.release();
                theAuthKeyId.get()->issuer = genNames.release();
                theAuthKeyId.get()->serial = issuerSerial.release();
            }
        }
    }

    // The Authority Key Identifier extension should include KeyId or/and both
    /// issuer name and issuer serial
    if (!theAuthKeyId.get()->keyid && (!theAuthKeyId.get()->issuer || !theAuthKeyId.get()->serial))
        return false;

    const X509V3_EXT_METHOD *method = X509V3_EXT_get_nid(NID_authority_key_identifier);
    if (!method)
        return false;

    unsigned char *ext_der = nullptr;
    int ext_len = ASN1_item_i2d((ASN1_VALUE *)theAuthKeyId.get(), &ext_der, ASN1_ITEM_ptr(method->it));
    Ssl::ASN1_OCTET_STRING_Pointer extOct(ASN1_OCTET_STRING_new());
    extOct.get()->data = ext_der;
    extOct.get()->length = ext_len;
    Ssl::X509_EXTENSION_Pointer extAuthKeyId(X509_EXTENSION_create_by_NID(nullptr, NID_authority_key_identifier, 0, extOct.get()));
    if (!extAuthKeyId.get())
        return false;

    extOct.release();
    if (!X509_add_ext(cert.get(), extAuthKeyId.get(), -1))
        return false;

    return true;
}

/// Copy certificate extensions from cert to mimicCert.
/// Returns the number of extensions copied.
// Currently only extensions which are reported by the users that required are
// mimicked. More safe to mimic extensions would be added here if users request
// them.
static int
mimicExtensions(Security::CertPointer & cert, Security::CertPointer const &mimicCert, Security::CertPointer const &issuerCert)
{
    static int extensions[]= {
        NID_key_usage,
        NID_ext_key_usage,
        NID_basic_constraints,
        0
    };

    // key usage bit names
    enum {
        DigitalSignature,
        NonRepudiation,
        KeyEncipherment, // NSS requires for RSA but not EC
        DataEncipherment,
        KeyAgreement,
        KeyCertificateSign,
        CRLSign,
        EncipherOnly,
        DecipherOnly
    };

    // XXX: Add PublicKeyPointer. In OpenSSL, public and private keys are
    // internally represented by EVP_PKEY pair, but GnuTLS uses distinct types.
    const Security::PrivateKeyPointer certKey(X509_get_pubkey(mimicCert.get()));
#if OPENSSL_VERSION_MAJOR < 3
    const auto rsaPkey = EVP_PKEY_get0_RSA(certKey.get()) != nullptr;
#else
    const auto rsaPkey = EVP_PKEY_is_a(certKey.get(), "RSA") == 1;
#endif

    int added = 0;
    int nid;
    for (int i = 0; (nid = extensions[i]) != 0; ++i) {
        const int pos = X509_get_ext_by_NID(mimicCert.get(), nid, -1);
        if (X509_EXTENSION *ext = X509_get_ext(mimicCert.get(), pos)) {
            // Mimic extension exactly.
            if (X509_add_ext(cert.get(), ext, -1))
                ++added;
            if (nid == NID_key_usage && !rsaPkey) {
                // NSS does not require the KeyEncipherment flag on EC keys
                // but it does require it for RSA keys.  Since ssl-bump
                // substitutes RSA keys for EC ones, we need to ensure that
                // that the more stringent requirements are met.

                const int p = X509_get_ext_by_NID(cert.get(), NID_key_usage, -1);
                if ((ext = X509_get_ext(cert.get(), p)) != nullptr) {
                    ASN1_BIT_STRING *keyusage = (ASN1_BIT_STRING *)X509V3_EXT_d2i(ext);
                    ASN1_BIT_STRING_set_bit(keyusage, KeyEncipherment, 1);

                    //Build the ASN1_OCTET_STRING
                    const X509V3_EXT_METHOD *method = X509V3_EXT_get(ext);
                    assert(method && method->it);
                    unsigned char *ext_der = nullptr;
                    int ext_len = ASN1_item_i2d((ASN1_VALUE *)keyusage,
                                                &ext_der,
                                                (const ASN1_ITEM *)ASN1_ITEM_ptr(method->it));

                    ASN1_OCTET_STRING *ext_oct = ASN1_OCTET_STRING_new();
                    ext_oct->data = ext_der;
                    ext_oct->length = ext_len;
                    X509_EXTENSION_set_data(ext, ext_oct);

                    ASN1_OCTET_STRING_free(ext_oct);
                    ASN1_BIT_STRING_free(keyusage);
                }
            }
        }
    }

    if (mimicAuthorityKeyId(cert, mimicCert, issuerCert))
        ++added;

    // We could also restrict mimicking of the CA extension to CA:FALSE
    // because Squid does not generate valid fake CA certificates.

    return added;
}

/// Adds a new subjectAltName extension contining Subject CN or returns false
/// expects the caller to check for the existing subjectAltName extension
static bool
addAltNameWithSubjectCn(Security::CertPointer &cert)
{
    X509_NAME *name = X509_get_subject_name(cert.get());
    if (!name)
        return false;

    const int loc = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (loc < 0)
        return false;

    ASN1_STRING *cn_data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, loc));
    if (!cn_data)
        return false;

    char dnsName[1024]; // DNS names are limited to 256 characters
    const int res = snprintf(dnsName, sizeof(dnsName), "DNS:%*s", cn_data->length, cn_data->data);
    if (res <= 0 || res >= static_cast<int>(sizeof(dnsName)))
        return false;

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, dnsName);
    if (!ext)
        return false;

    const bool result = X509_add_ext(cert.get(), ext, -1);

    X509_EXTENSION_free(ext);
    return result;
}

static bool buildCertificate(Security::CertPointer & cert, Ssl::CertificateProperties const &properties)
{
    // not an Ssl::X509_NAME_Pointer because X509_REQ_get_subject_name()
    // returns a pointer to the existing subject name. Nothing to clean here.
    if (properties.mimicCert.get()) {
        // Leave subject empty if we cannot extract it from true cert.
        if (X509_NAME *name = X509_get_subject_name(properties.mimicCert.get())) {
            // X509_set_subject_name will call X509_dup for name
            X509_set_subject_name(cert.get(), name);
        }
    }

    if (properties.setCommonName || !properties.mimicCert.get()) {
        // In this case the CN of the certificate given by the user
        // Ignore errors: it is better to make a certificate with no CN
        // than to quit ssl-crtd helper because we cannot make a certificate.
        // Most errors are caused by user input such as huge domain names.
        (void)replaceCommonName(cert, properties.commonName);
    }

    // We should get caCert notBefore and notAfter fields and do not allow
    // notBefore/notAfter values from certToMimic before/after notBefore/notAfter
    // fields from caCert.
    // Currently there is not any way in openssl tollkit to compare two ASN1_TIME
    // objects.
    ASN1_TIME *aTime = nullptr;
    if (!properties.setValidBefore && properties.mimicCert.get())
        aTime = X509_getm_notBefore(properties.mimicCert.get());
    if (!aTime && properties.signWithX509.get())
        aTime = X509_getm_notBefore(properties.signWithX509.get());

    if (aTime) {
        if (!X509_set1_notBefore(cert.get(), aTime))
            return false;
    } else if (!X509_gmtime_adj(X509_getm_notBefore(cert.get()), (-2)*24*60*60))
        return false;

    aTime = nullptr;
    if (!properties.setValidAfter && properties.mimicCert.get())
        aTime = X509_getm_notAfter(properties.mimicCert.get());
    if (!aTime && properties.signWithX509.get())
        aTime = X509_getm_notAfter(properties.signWithX509.get());
    if (aTime) {
        if (!X509_set1_notAfter(cert.get(), aTime))
            return false;
    } else if (!X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60*60*24*365*3))
        return false;

    int addedExtensions = 0;
    bool useCommonNameAsAltName = true;
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
            int pos = X509_get_ext_by_NID(properties.mimicCert.get(), NID_subject_alt_name, -1);
            X509_EXTENSION *ext=X509_get_ext(properties.mimicCert.get(), pos);
            if (ext) {
                if (X509_add_ext(cert.get(), ext, -1))
                    ++addedExtensions;
            }
            // We want to mimic the server-sent subjectAltName, not enhance it.
            useCommonNameAsAltName = false;
        }

        addedExtensions += mimicExtensions(cert, properties.mimicCert, properties.signWithX509);
    }

    if (useCommonNameAsAltName && addAltNameWithSubjectCn(cert))
        ++addedExtensions;

    // According to RFC 5280, using extensions requires v3 certificate.
    if (addedExtensions)
        X509_set_version(cert.get(), 2); // value 2 means v3

    return true;
}

static bool generateFakeSslCertificate(Security::CertPointer & certToStore, Security::PrivateKeyPointer & pkeyToStore, Ssl::CertificateProperties const &properties,  Ssl::BIGNUM_Pointer const &serial)
{
    // Use signing certificates private key as generated certificate private key
    const auto pkey = properties.signWithPkey ? properties.signWithPkey : CreateRsaPrivateKey();
    if (!pkey)
        return false;

    Security::CertPointer cert(X509_new());
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

    const  EVP_MD *hash = properties.signHash ? properties.signHash : EVP_get_digestbyname(SQUID_SSL_SIGN_HASH_IF_NONE);
    assert(hash);
    /*Now sign the request */
    if (properties.signAlgorithm != Ssl::algSignSelf && properties.signWithPkey.get())
        ret = X509_sign(cert.get(), properties.signWithPkey.get(), hash);
    else //else sign with self key (self signed request)
        ret = X509_sign(cert.get(), pkey.get(), hash);

    if (!ret)
        return false;

    certToStore = std::move(cert);
    pkeyToStore = std::move(pkey);
    return true;
}

static  BIGNUM *createCertSerial(unsigned char *md, unsigned int n)
{

    assert(n == 20); //for sha1 n is 20 (for md5 n is 16)

    BIGNUM *serial = nullptr;
    serial = BN_bin2bn(md, n, nullptr);

    // if the serial is "0" set it to '1'
    if (BN_is_zero(serial) == true)
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
static BIGNUM *x509Digest(Security::CertPointer const & cert)
{
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!X509_digest(cert.get(),EVP_sha1(),md,&n))
        return nullptr;

    return createCertSerial(md, n);
}

static BIGNUM *x509Pubkeydigest(Security::CertPointer const & cert)
{
    unsigned int n;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (!X509_pubkey_digest(cert.get(),EVP_sha1(),md,&n))
        return nullptr;

    return createCertSerial(md, n);
}

/// Generate a unique serial number based on a Ssl::CertificateProperties object
/// for a new generated certificate
static bool createSerial(Ssl::BIGNUM_Pointer &serial, Ssl::CertificateProperties const &properties)
{
    Security::PrivateKeyPointer fakePkey;
    Security::CertPointer fakeCert;

    serial.reset(x509Pubkeydigest(properties.signWithX509));
    if (!serial.get()) {
        serial.reset(BN_new());
        BN_zero(serial.get());
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

bool Ssl::generateSslCertificate(Security::CertPointer & certToStore, Security::PrivateKeyPointer & pkeyToStore, Ssl::CertificateProperties const &properties)
{
    Ssl::BIGNUM_Pointer serial;

    if (!createSerial(serial, properties))
        return false;

    return  generateFakeSslCertificate(certToStore, pkeyToStore, properties, serial);
}

bool
Ssl::OpenCertsFileForReading(Ssl::BIO_Pointer &bio, const char *filename)
{
    bio.reset(BIO_new(BIO_s_file()));
    if (!bio)
        return false;
    if (!BIO_read_filename(bio.get(), filename))
        return false;
    return true;
}

Security::CertPointer
Ssl::ReadOptionalCertificate(const BIO_Pointer &bio)
{
    Assure(bio);
    ForgetErrors();
    if (const auto cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr))
        return Security::CertPointer(cert);
    const auto savedErrno = errno;

    // PEM_R_NO_START_LINE means OpenSSL could not find a BEGIN CERTIFICATE
    // marker after successfully reading input. That includes such use cases as
    // empty input, valid input exhausted by previous extractions, malformed
    // input, and valid key-only input without the certificate. We cannot
    // distinguish all these outcomes and treat this error as an EOF condition.
    if (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE) {
        // consume PEM_R_NO_START_LINE to clean global error queue (if that was
        // the only error) and/or to let us check for other errors (otherwise)
        (void)ERR_get_error();
        if (!ERR_peek_last_error())
            return nullptr; // EOF without any other errors
    }

    ThrowErrors("cannot read a PEM-encoded certificate", savedErrno, Here());
}

Security::CertPointer
Ssl::ReadCertificate(const BIO_Pointer &bio)
{
    if (const auto cert = ReadOptionalCertificate(bio))
        return cert;

    // PEM_R_NO_START_LINE
    throw TextException("missing a required PEM-encoded certificate", Here());
}

bool
Ssl::ReadPrivateKey(Ssl::BIO_Pointer &bio, Security::PrivateKeyPointer &pkey, pem_password_cb *passwd_callback)
{
    assert(bio);
    if (EVP_PKEY *akey = PEM_read_bio_PrivateKey(bio.get(), nullptr, passwd_callback, nullptr)) {
        pkey.resetWithoutLocking(akey);
        return true;
    }
    return false;
}

void
Ssl::ReadPrivateKeyFromFile(char const * keyFilename, Security::PrivateKeyPointer &pkey, pem_password_cb *passwd_callback)
{
    if (!keyFilename)
        return;
    Ssl::BIO_Pointer bio;
    if (!OpenCertsFileForReading(bio, keyFilename))
        return;
    ReadPrivateKey(bio, pkey, passwd_callback);
}

bool
Ssl::OpenCertsFileForWriting(Ssl::BIO_Pointer &bio, const char *filename)
{
    bio.reset(BIO_new(BIO_s_file()));
    if (!bio)
        return false;
    if (!BIO_write_filename(bio.get(), const_cast<char *>(filename)))
        return false;
    return true;
}

bool
Ssl::WriteX509Certificate(Ssl::BIO_Pointer &bio, const Security::CertPointer & cert)
{
    if (!cert || !bio)
        return false;
    if (!PEM_write_bio_X509(bio.get(), cert.get()))
        return false;
    return true;
}

bool
Ssl::WritePrivateKey(Ssl::BIO_Pointer &bio, const Security::PrivateKeyPointer &pkey)
{
    if (!pkey || !bio)
        return false;
    if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr))
        return false;
    return true;
}

Ssl::UniqueCString
Ssl::OneLineSummary(X509_NAME &name)
{
    return Ssl::UniqueCString(X509_NAME_oneline(&name, nullptr, 0));
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
    } else // if (aTime->type == V_ASN1_GENERALIZEDTIME)
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
        assert(properties.signWithX509.get());
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
    } else if (properties.commonName != CommonHostName(cert))
        return false;

    if (!properties.setValidBefore) {
        const auto aTime = X509_getm_notBefore(cert);
        const auto bTime = X509_getm_notBefore(cert2);
        if (asn1time_cmp(aTime, bTime) != 0)
            return false;
    } else if (X509_cmp_current_time(X509_getm_notBefore(cert)) >= 0) {
        // notBefore does not exist (=0) or it is in the future (>0)
        return false;
    }

    if (!properties.setValidAfter) {
        const auto aTime = X509_getm_notAfter(cert);
        const auto bTime = X509_getm_notAfter(cert2);
        if (asn1time_cmp(aTime, bTime) != 0)
            return false;
    } else if (X509_cmp_current_time(X509_getm_notAfter(cert)) <= 0) {
        // notAfter does not exist (0) or  it is in the past (<0)
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
    cert1_altnames = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    STACK_OF(GENERAL_NAME) * cert2_altnames;
    cert2_altnames = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert2, NID_subject_alt_name, nullptr, nullptr);
    bool match = true;
    if (cert1_altnames) {
        int numalts = sk_GENERAL_NAME_num(cert1_altnames);
        for (int i = 0; match && i < numalts; ++i) {
            GENERAL_NAME *aName = sk_GENERAL_NAME_value(cert1_altnames, i);
            match = sk_GENERAL_NAME_find(cert2_altnames, aName);
        }
    } else if (cert2_altnames)
        match = false;

    sk_GENERAL_NAME_pop_free(cert1_altnames, GENERAL_NAME_free);
    sk_GENERAL_NAME_pop_free(cert2_altnames, GENERAL_NAME_free);

    return match;
}

static const char *getSubjectEntry(X509 *x509, int nid)
{
    static char name[1024] = ""; // stores common name (CN)

    if (!x509)
        return nullptr;

    // TODO: What if the entry is a UTF8String? See X509_NAME_get_index_by_NID(3ssl).
    const int nameLen = X509_NAME_get_text_by_NID(
                            X509_get_subject_name(x509),
                            nid,  name, sizeof(name));

    if (nameLen > 0)
        return name;

    return nullptr;
}

const char *Ssl::CommonHostName(X509 *x509)
{
    return getSubjectEntry(x509, NID_commonName);
}

const char *Ssl::getOrganization(X509 *x509)
{
    return getSubjectEntry(x509, NID_organizationName);
}

bool
Ssl::CertificatesCmp(const Security::CertPointer &cert1, const Security::CertPointer &cert2)
{
    if (!cert1 || ! cert2)
        return false;

    int cert1Len;
    unsigned char *cert1Asn = nullptr;
    cert1Len = ASN1_item_i2d((ASN1_VALUE *)cert1.get(), &cert1Asn, ASN1_ITEM_rptr(X509));

    int cert2Len;
    unsigned char *cert2Asn = nullptr;
    cert2Len = ASN1_item_i2d((ASN1_VALUE *)cert2.get(), &cert2Asn, ASN1_ITEM_rptr(X509));

    if (cert1Len != cert2Len)
        return false;

    bool ret = (memcmp(cert1Asn, cert2Asn, cert1Len) == 0);

    OPENSSL_free(cert1Asn);
    OPENSSL_free(cert2Asn);

    return ret;
}

const ASN1_BIT_STRING *
Ssl::X509_get_signature(const Security::CertPointer &cert)
{
    SQUID_CONST_X509_GET0_SIGNATURE_ARGS ASN1_BIT_STRING *sig = nullptr;
    SQUID_CONST_X509_GET0_SIGNATURE_ARGS X509_ALGOR *sig_alg = nullptr;

    X509_get0_signature(&sig, &sig_alg, cert.get());
    return sig;
}

