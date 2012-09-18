#include "squid.h"
#include "acl/FilledChecklist.h"
#include "ssl/support.h"
#include "ssl/cert_validate_message.h"
#include "ssl/ErrorDetail.h"


void
Ssl::CertValidateMessage::composeRequest(ValidateCertificate const &vcert)
{
    body.clear();
    body += Ssl::CertValidateMessage::param_host + "=" + vcert.domainName;
    if (vcert.errors) {
        body += "\n" + Ssl::CertValidateMessage::param_error + "=";
        bool comma = false;
        for (const Ssl::Errors *err = vcert.errors; err; err = err->next ) {
            if (comma)
                body += ",";
            body += GetErrorName(err->element);
            comma = true;
        }
    }

    if (vcert.peerCerts) {
        body +="\n";
        Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
        for (int i = 0; i < sk_X509_num(vcert.peerCerts); ++i) {
            X509 *cert = sk_X509_value(vcert.peerCerts, i);
            PEM_write_bio_X509(bio.get(), cert);
            body = body + "cert_" + xitoa(i) + "=";
            char *ptr;
            long len = BIO_get_mem_data(bio.get(), &ptr);
            body.append(ptr, len);
            // Normally openssl toolkit terminates Certificate with a '\n'.
            if (ptr[len-1] != '\n')
                body +="\n";
            if (!BIO_reset(bio.get())) {
                // print an error?
            }
        }
    }
}

static int
get_error_id(const char *label, size_t len)
{
    const char *e = label + len -1;
    while (e != label && xisdigit(*e)) --e;
    if (e != label) ++e;
    return strtol(e, 0 , 10);
}

bool
Ssl::CertValidateMessage::parseResponse(ValidateCertificateResponse &resp, STACK_OF(X509) *peerCerts, std::string &error)
{
    std::vector<CertItem> certs;

    const char *param = body.c_str();
    while(*param) {
        while(xisspace(*param)) param++;
        if (! *param)
            break;

        size_t param_len = strcspn(param, "=\r\n");
        if (param[param_len] !=  '=') {
            debugs(83, 2, "Cert validator response parse error: " << param);
            return false;
        }
        const char *value=param+param_len+1;

        if (param_len > param_cert.length() && 
            strncmp(param, param_cert.c_str(), param_cert.length()) == 0) {
            CertItem ci;
            ci.name.assign(param, param_len); 
            X509_Pointer x509;
            readCertFromMemory(x509, value);
            ci.setCert(x509.get());
            certs.push_back(ci);

            const char *b = strstr(value, "-----END CERTIFICATE-----");
            if (b == NULL) {
                debugs(83, 2, "Cert Vailidator response parse error: Failed  to find certificate boundary " << value);
                return false;
            }
            b += strlen("-----END CERTIFICATE-----");
            param = b + 1;
            continue;
        }

        size_t value_len = strcspn(value, "\r\n");
        std::string v(value, value_len);

        debugs(83, 5, HERE << "Returned value: " << std::string(param, param_len).c_str() << ": " << 
               v.c_str());

        int errorId = get_error_id(param, param_len);
        Ssl::ValidateCertificateResponse::ErrorItem &currentItem = resp.getError(errorId);

        if (param_len > param_error_name.length() && 
            strncmp(param, param_error_name.c_str(), param_error_name.length()) == 0){
            currentItem.error_no = Ssl::GetErrorCode(v.c_str());
            if (currentItem.error_no == SSL_ERROR_NONE) {
                debugs(83, 2, "Cert validator response parse error: Unknown SSL Error: " << v);
                return false;
            }
        } else if (param_len > param_error_reason.length() && 
                   strncmp(param, param_error_reason.c_str(), param_error_reason.length()) == 0) {
            currentItem.error_reason = v;
        } else if (param_len > param_error_cert.length() &&
                   strncmp(param, param_error_cert.c_str(), param_error_cert.length()) == 0) {

            if (X509 *cert = getCertByName(certs, v)) {
                debugs(83, 6, HERE << "The certificate with id \"" << v << "\" found.");
                currentItem.setCert(cert);
            } else {
                //In this case we assume that the certID is one of the certificates sent
                // to cert validator. The certificates sent to cert validator have names in
                // form "cert_xx" where the "xx" is an integer represents the position of
                // the certificate inside peer certificates list.
                int certId = get_error_id(v.c_str(), v.length());
                debugs(83, 6, HERE << "Cert index in peer certificates list:" << certId);
                //if certId is not correct sk_X509_value returns NULL
                currentItem.setCert(sk_X509_value(peerCerts, certId));
            }
        } else {
            debugs(83, 2, "Cert validator response parse error: Unknown parameter name " << std::string(param, param_len).c_str());
            return false;
        }
        

        param = value + value_len +1;
    }

    /*Run through parsed errors to check for errors*/

    return true;
}

X509 *
Ssl::CertValidateMessage::getCertByName(std::vector<CertItem> const &certs, std::string const & name)
{
    for (std::vector<CertItem>::const_iterator ci = certs.begin(); ci != certs.end(); ++ci) {
        if (ci->name.compare(name) == 0)
            return ci->cert;
    }
    return NULL;
}

Ssl::ValidateCertificateResponse::ErrorItem &
Ssl::ValidateCertificateResponse::getError(int errorId)
{
    for(Ssl::ValidateCertificateResponse::Errors::iterator i = errors.begin(); i != errors.end(); ++i){
        if (i->id == errorId)
            return *i;
    }
    Ssl::ValidateCertificateResponse::ErrorItem errItem;
    errItem.id = errorId;
    errors.push_back(errItem);
    return errors.back();
}

Ssl::ValidateCertificateResponse::ErrorItem::ErrorItem(const ErrorItem &old) {
    error_no = old.error_no;
    error_reason = old.error_reason;
    cert = NULL;
    setCert(old.cert);
}

Ssl::ValidateCertificateResponse::ErrorItem::~ErrorItem() {
    if (cert)
        X509_free(cert);
}

Ssl::ValidateCertificateResponse::ErrorItem & Ssl::ValidateCertificateResponse::ErrorItem::operator = (const ErrorItem &old) {
    error_no = old.error_no;
    error_reason = old.error_reason;
    setCert(old.cert);
    return *this;
}

void
Ssl::ValidateCertificateResponse::ErrorItem::setCert(X509 *aCert) {
    if (cert)
        X509_free(cert);
    if (aCert) {
        cert = aCert;
        CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
    } else
        cert = NULL;
}

void
Ssl::ValidateCertificateResponse::ErrorItem::clear() {
    error_no = SSL_ERROR_NONE;
    error_reason = "";
    if (cert)
        X509_free(cert);
    cert = NULL;
}

Ssl::CertValidateMessage::CertItem::CertItem(const CertItem &old)
{
    name = old.name;
    cert = NULL;
    setCert(old.cert);
}

Ssl::CertValidateMessage::CertItem & Ssl::CertValidateMessage::CertItem::operator = (const CertItem &old)
{
    name = old.name;
    setCert(old.cert);
    return *this;
}

Ssl::CertValidateMessage::CertItem::~CertItem()
{
    if (cert)
        X509_free(cert);
}

void
Ssl::CertValidateMessage::CertItem::setCert(X509 *aCert)
{
    if (cert)
        X509_free(cert);
    if (aCert) {
        cert = aCert;
        CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
    } else
        cert = NULL;
}

const std::string Ssl::CertValidateMessage::code_cert_validate("cert_validate");
const std::string Ssl::CertValidateMessage::param_domain("domain");
const std::string Ssl::CertValidateMessage::param_error("errors");
const std::string Ssl::CertValidateMessage::param_cert("cert_");
const std::string Ssl::CertValidateMessage::param_error_name("error_name_"); 
const std::string Ssl::CertValidateMessage::param_error_reason("error_reason_");
const std::string Ssl::CertValidateMessage::param_error_cert("error_cert_");

