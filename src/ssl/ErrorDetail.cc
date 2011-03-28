#include "squid.h"
#include "ssl/ErrorDetail.h"
#if HAVE_MAP
#include <map>
#endif

struct SslErrorDetailEntry {
    Ssl::ssl_error_t value;
    const char *name;
    const char *detail; ///< for error page %D macro expansion; may contain macros
    const char *descr; ///< short error description (for use in debug messages or error pages) 
};

static const char *SslErrorDetailDefaultStr = "SSL certificate validation error (%err_name): %ssl_subject";
//Use std::map to optimize search
typedef std::map<Ssl::ssl_error_t, const SslErrorDetailEntry *> SslErrorDetails;
SslErrorDetails TheSslDetail;

static SslErrorDetailEntry TheSslDetailArray[] = {
    {X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, 
     "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT",
     "%err_name: SSL Certficate error: certificate issuer (CA) not known: %ssl_ca_name",
     "Unable to get issuer certificate"},
    {X509_V_ERR_UNABLE_TO_GET_CRL, 
     "X509_V_ERR_UNABLE_TO_GET_CRL",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Unable to get certificate CRL"},
    {X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE, 
     "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Unable to decrypt certificate's signature"},
    {X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE, 
     "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Unable to decrypt CRL's signature"},
    {X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY, 
     "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
     "%err_name: Unable to decode issuer (CA) public key: %ssl_ca_name",
     "Unable to decode issuer public key"},
    {X509_V_ERR_CERT_SIGNATURE_FAILURE, 
     "X509_V_ERR_CERT_SIGNATURE_FAILURE",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Certificate signature failure"},
    {X509_V_ERR_CRL_SIGNATURE_FAILURE,
     "X509_V_ERR_CRL_SIGNATURE_FAILURE",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "CRL signature failure"},
    {X509_V_ERR_CERT_NOT_YET_VALID,
     "X509_V_ERR_CERT_NOT_YET_VALID",
     "%err_name: SSL Certficate is not valid before: %ssl_notbefore",
     "Certificate is not yet valid"},
    {X509_V_ERR_CERT_HAS_EXPIRED,
     "X509_V_ERR_CERT_HAS_EXPIRED",
     "%err_name: SSL Certificate expired on: %ssl_notafter",
     "Certificate has expired"},
    {X509_V_ERR_CRL_NOT_YET_VALID,
     "X509_V_ERR_CRL_NOT_YET_VALID",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "CRL is not yet valid"},
    {X509_V_ERR_CRL_HAS_EXPIRED,
     "X509_V_ERR_CRL_HAS_EXPIRED",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "CRL has expired"},
    {X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
     "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD",
     "%err_name: SSL Certificate has invalid start date (the 'not before' field): %ssl_subject",
     "Format error in certificate's notBefore field"},
    {X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD,
     "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD",
     "%err_name: SSL Certificate has invalid expiration date (the 'not after' field): %ssl_subject",
     "Format error in certificate's notAfter field"},
    {X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
     "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Format error in CRL's lastUpdate field"},
    {X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
     "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Format error in CRL's nextUpdate field"},
    {X509_V_ERR_OUT_OF_MEM,
     "X509_V_ERR_OUT_OF_MEM",
     "%err_name: %ssl_error_descr",
     "Out of memory"},
    {X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
     "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT",
     "%err_name: Self-signed SSL Certificate: %ssl_subject",
     "Self signed certificate"},
    {X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
     "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN",
     "%err_name: Self-signed SSL Certificate in chain: %ssl_subject",
     "Self signed certificate in certificate chain"},
    {X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
     "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
     "%err_name: SSL Certficate error: certificate issuer (CA) not known: %ssl_ca_name",
     "Unable to get local issuer certificate"},
    {X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
     "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Unable to verify the first certificate"},
    {X509_V_ERR_CERT_CHAIN_TOO_LONG,
     "X509_V_ERR_CERT_CHAIN_TOO_LONG",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Certificate chain too long"},
    {X509_V_ERR_CERT_REVOKED,
     "X509_V_ERR_CERT_REVOKED",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Certificate revoked"},
    {X509_V_ERR_INVALID_CA,
     "X509_V_ERR_INVALID_CA",
     "%err_name: %ssl_error_descr: %ssl_ca_name",
     "Invalid CA certificate"},
    {X509_V_ERR_PATH_LENGTH_EXCEEDED,
     "X509_V_ERR_PATH_LENGTH_EXCEEDED",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Path length constraint exceeded"},
    {X509_V_ERR_INVALID_PURPOSE,
     "X509_V_ERR_INVALID_PURPOSE",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Unsupported certificate purpose"},
    {X509_V_ERR_CERT_UNTRUSTED,
     "X509_V_ERR_CERT_UNTRUSTED",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Certificate not trusted"},
    {X509_V_ERR_CERT_REJECTED,
     "X509_V_ERR_CERT_REJECTED",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Certificate rejected"},
    {X509_V_ERR_SUBJECT_ISSUER_MISMATCH,
     "X509_V_ERR_SUBJECT_ISSUER_MISMATCH",
     "%err_name: %ssl_error_descr: %ssl_ca_name",
     "Subject issuer mismatch"},
    {X509_V_ERR_AKID_SKID_MISMATCH,
     "X509_V_ERR_AKID_SKID_MISMATCH",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Authority and subject key identifier mismatch"},
    {X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH,
     "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH",
     "%err_name: %ssl_error_descr: %ssl_ca_name",
     "Authority and issuer serial number mismatch"},
    {X509_V_ERR_KEYUSAGE_NO_CERTSIGN,
     "X509_V_ERR_KEYUSAGE_NO_CERTSIGN",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Key usage does not include certificate signing"},
    {X509_V_ERR_APPLICATION_VERIFICATION,
     "X509_V_ERR_APPLICATION_VERIFICATION",
     "%err_name: %ssl_error_descr: %ssl_subject",
     "Application verification failure"},
    { SSL_ERROR_NONE, "SSL_ERROR_NONE", "%err_name: No error", "No error" },
    {SSL_ERROR_NONE, NULL, NULL, NULL }
};

static void loadSslDetailMap()
{
    assert(TheSslDetail.empty());
    for (int i = 0; TheSslDetailArray[i].name; ++i) {
        TheSslDetail[TheSslDetailArray[i].value] = &TheSslDetailArray[i];
    }
}

Ssl::ssl_error_t
Ssl::parseErrorString(const char *name)
{
    assert(name);

    if (TheSslDetail.empty())
        loadSslDetailMap();

    typedef SslErrorDetails::const_iterator SEDCI;
    for (SEDCI i = TheSslDetail.begin(); i != TheSslDetail.end(); ++i) {
        if (strcmp(name, i->second->name) == 0)
            return i->second->value;
    }

    if (xisdigit(*name)) {
        const long int value = strtol(name, NULL, 0);
        if (SQUID_SSL_ERROR_MIN <= value && value <= SQUID_SSL_ERROR_MAX)
            return value;
        fatalf("Too small or too bug SSL error code '%s'", name);
    }

    fatalf("Unknown SSL error name '%s'", name);
    return SSL_ERROR_SSL; // not reached
}

static const SslErrorDetailEntry *getErrorRecord(Ssl::ssl_error_t value)
{
    if (TheSslDetail.empty())
        loadSslDetailMap();

    const SslErrorDetails::const_iterator it = TheSslDetail.find(value);
    if (it != TheSslDetail.end())
        return it->second;

    return NULL;
}

const char *
Ssl::getErrorName(Ssl::ssl_error_t value)
{
    if (const SslErrorDetailEntry *errorRecord = getErrorRecord(value))
        return errorRecord->name;

    return NULL;
}

static const char *getErrorDetail(Ssl::ssl_error_t value)
{
    if (const SslErrorDetailEntry *errorRecord = getErrorRecord(value))
        return errorRecord->detail;

    // we must always return something because ErrorDetail::buildDetail
    // will hit an assertion
    return SslErrorDetailDefaultStr;
}

const char *
Ssl::GetErrorDescr(Ssl::ssl_error_t value)
{
    if (const SslErrorDetailEntry *errorRecord = getErrorRecord(value))
        return errorRecord->descr;

    return NULL;
}

Ssl::ErrorDetail::err_frm_code Ssl::ErrorDetail::ErrorFormatingCodes[] = {
    {"ssl_subject", &Ssl::ErrorDetail::subject},
    {"ssl_ca_name", &Ssl::ErrorDetail::ca_name},
    {"ssl_cn", &Ssl::ErrorDetail::cn},
    {"ssl_notbefore", &Ssl::ErrorDetail::notbefore},
    {"ssl_notafter", &Ssl::ErrorDetail::notafter},
    {"err_name", &Ssl::ErrorDetail::err_code},
    {"ssl_error_descr", &Ssl::ErrorDetail::err_descr},
    {NULL,NULL}
};

/**
 * The subject of the current certification in text form
 */
const char  *Ssl::ErrorDetail::subject() const
{
    if (!peer_cert)
        return "[Not available]";

    static char tmpBuffer[256]; // A temporary buffer
    X509_NAME_oneline(X509_get_subject_name(peer_cert.get()), tmpBuffer,
                      sizeof(tmpBuffer));
    return tmpBuffer;
}

// helper function to be used with Ssl::matchX509CommonNames
static int copy_cn(void *check_data,  ASN1_STRING *cn_data)
{
    String *str = (String *)check_data;
    if (!str) // no data? abort
        return 0;
    if (str->defined())
        str->append(", ");
    str->append((const char *)cn_data->data, cn_data->length);
    return 1;
}

/**
 * The list with certificates cn and alternate names
 */
const char *Ssl::ErrorDetail::cn() const
{
    if (!peer_cert)
        return "[Not available]";

    static String tmpStr;  ///< A temporary string buffer
    tmpStr.clean();
    Ssl::matchX509CommonNames(peer_cert.get(), &tmpStr, copy_cn);
    return tmpStr.termedBuf();
}

/**
 * The issuer name
 */
const char *Ssl::ErrorDetail::ca_name() const
{
    if (!peer_cert)
        return "[Not available]";

    static char tmpBuffer[256]; // A temporary buffer
    X509_NAME_oneline(X509_get_issuer_name(peer_cert.get()), tmpBuffer, sizeof(tmpBuffer));
    return tmpBuffer;
}

/**
 * The certificate "not before" field
 */
const char *Ssl::ErrorDetail::notbefore() const
{
    if (!peer_cert)
        return "[Not available]";

    static char tmpBuffer[256]; // A temporary buffer
    ASN1_UTCTIME * tm = X509_get_notBefore(peer_cert.get());
    Ssl::asn1timeToString(tm, tmpBuffer, sizeof(tmpBuffer));
    return tmpBuffer;
}

/**
 * The certificate "not after" field
 */
const char *Ssl::ErrorDetail::notafter() const
{
    if (!peer_cert)
        return "[Not available]";

    static char tmpBuffer[256]; // A temporary buffer
    ASN1_UTCTIME * tm = X509_get_notAfter(peer_cert.get());
    Ssl::asn1timeToString(tm, tmpBuffer, sizeof(tmpBuffer));
    return tmpBuffer;
}

/**
 * The string representation of the error_no
 */
const char *Ssl::ErrorDetail::err_code() const
{
    static char tmpBuffer[64];
    const char *err = getErrorName(error_no);
    if (!err) {
        snprintf(tmpBuffer, 64, "%d", (int)error_no);
        err = tmpBuffer;
    }
    return err;
}

/**
 * A short description of the error_no
 */
const char *Ssl::ErrorDetail::err_descr() const
{
    if (const char *err = GetErrorDescr(error_no))
        return err;
    return "[Not available]";
}

/**
 * It converts the code to a string value. Currently the following
 * formating codes are supported:
 * %err_name: The name of the SSL error
 * %ssl_error_descr: A short description of the SSL error
 * %ssl_cn: The comma-separated list of common and alternate names
 * %ssl_subject: The certificate subject
 * %ssl_ca_name: The certificate issuer name
 * %ssl_notbefore: The certificate "not before" field
 * %ssl_notafter: The certificate "not after" field
 \retval  the length of the code (the number of characters will be replaced by value)
*/
int Ssl::ErrorDetail::convert(const char *code, const char **value) const
{
    *value = "-";
    for (int i=0; ErrorFormatingCodes[i].code!=NULL; i++) {
        const int len = strlen(ErrorFormatingCodes[i].code);
        if (strncmp(code,ErrorFormatingCodes[i].code, len)==0) {
            ErrorDetail::fmt_action_t action  = ErrorFormatingCodes[i].fmt_action;
            *value = (this->*action)();
            return len;
        }
    }
    return 0;
}

/**
 * It uses the convert method to build the string errDetailStr using
 * a template message for the current SSL error. The template messages
 * can also contain normal error pages formating codes.
 * Currently the error template messages are hard-coded
 */
void Ssl::ErrorDetail::buildDetail() const
{
    char const *s = getErrorDetail(error_no);
    char const *p;
    char const *t;
    int code_len = 0;

    assert(s);
    while ((p = strchr(s, '%'))) {
        errDetailStr.append(s, p - s);
        code_len = convert(++p, &t);
        if (code_len)
            errDetailStr.append(t);
        else
            errDetailStr.append("%");
        s = p + code_len;
    }
    errDetailStr.append(s, strlen(s));
}

const String &Ssl::ErrorDetail::toString() const
{
    if (!errDetailStr.defined())
        buildDetail();
    return errDetailStr;
}

/* We may do not want to use X509_dup but instead
   internal SSL locking:
   CRYPTO_add(&(cert->references),1,CRYPTO_LOCK_X509);
   peer_cert.reset(cert);
*/
Ssl::ErrorDetail::ErrorDetail( Ssl::ssl_error_t err_no, X509 *cert): error_no (err_no)
{
    peer_cert.reset(X509_dup(cert));
}

Ssl::ErrorDetail::ErrorDetail(Ssl::ErrorDetail const &anErrDetail)
{
    error_no = anErrDetail.error_no;
    if (anErrDetail.peer_cert.get()) {
        peer_cert.reset(X509_dup(anErrDetail.peer_cert.get()));
    }
}
