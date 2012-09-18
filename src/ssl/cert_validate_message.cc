#include "squid.h"
#include "acl/FilledChecklist.h"
#include "ssl/support.h"
#include "ssl/cert_validate_message.h"
#include "ssl/ErrorDetail.h"


void Ssl::CertValidateMessage::composeRequest(ValidateCertificate const &vcert)
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

static int get_error_id(const char *label, size_t len)
{
    const char *e = label + len -1;
    while (e != label && xisdigit(*e)) --e;
    if (e != label) ++e;
    return strtol(e, 0 , 10);
}

bool Ssl::CertValidateMessage::parseResponse(ValidateCertificateResponse &resp, STACK_OF(X509) *peerCerts, std::string &error)
{
    int current_errorId = -1;
    std::vector<Ssl::ValidateCertificateResponse::CertItem> certs;

    Ssl::ValidateCertificateResponse::ErrorItem currentItem;

    const char *param = body.c_str();
    while(*param) {
        while(xisspace(*param)) param++;
        if (! *param)
            break;

        size_t param_len = strcspn(param, "=\r\n");
        if (param[param_len] !=  '=') {
            debugs(83, 2, "Error parsing: " << param);
            return false;
        }
        const char *value=param+param_len+1;

        if (param_len > param_cert.length() && 
            strncmp(param, param_cert.c_str(), param_cert.length()) == 0) {
            Ssl::ValidateCertificateResponse::CertItem ci;
            ci.name.assign(param, param_len); 
            X509_Pointer x509;
            readCertFromMemory(x509, value);
            ci.setCert(x509.get());
            certs.push_back(ci);

            const char *b = strstr(value, "-----END CERTIFICATE-----");
            if (b == NULL) {
                debugs(83, 2, "Parse error: Failed  to find certificate boundary " << value);
                return false;
            }
            b += strlen("-----END CERTIFICATE-----");
            param = b + 1;
            continue;
        }

        size_t value_len = strcspn(value, "\r\n");
        std::string v(value, value_len);

        debugs(83, 5, "Returned value: " << std::string(param, param_len).c_str() << ": " << 
               v.c_str());

        int errorId = get_error_id(param, param_len);

        if (current_errorId >=0 && errorId != current_errorId) {
            resp.errors.push_back(currentItem);  
            /*Reset current item:*/
            currentItem.clear();
        }
        current_errorId = errorId;

        if (param_len > param_error_name.length() && 
            strncmp(param, param_error_name.c_str(), param_error_name.length()) == 0){
            currentItem.error_no = Ssl::GetErrorCode(v.c_str());
        } else if (param_len > param_error_reason.length() && 
                   strncmp(param, param_error_reason.c_str(), param_error_reason.length()) == 0) {
            currentItem.error_reason = v;
        } else if (param_len > param_error_cert.length() &&
                   strncmp(param, param_error_cert.c_str(), param_error_cert.length()) == 0) {

            for (std::vector<Ssl::ValidateCertificateResponse::CertItem>::const_iterator ci = certs.begin(); ci != certs.end(); ++ci) {
                if (ci->name.compare(v) == 0) {
                    currentItem.setCert(ci->cert);
                    debugs(83, 6, HERE << "The custom cert \"" << ci->name << "\" used.");
                    break;
                }
            }
            if (!currentItem.cert) {
                int certId = get_error_id(v.c_str(), v.length());
                //if certId is not correct sk_X509_value returns NULL
                currentItem.setCert(sk_X509_value(peerCerts, certId));
                debugs(83, 6, HERE << "Cert ID read:" << certId);
            }
        } 

        param = value + value_len +1;
    }

    if (currentItem.error_no != SSL_ERROR_NONE)
        resp.errors.push_back(currentItem);

    return true;
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

Ssl::ValidateCertificateResponse::CertItem::CertItem(const CertItem &old)
{
    name = old.name;
    cert = NULL;
    setCert(old.cert);
}

Ssl::ValidateCertificateResponse::CertItem & Ssl::ValidateCertificateResponse::CertItem::operator = (const CertItem &old)
{
    name = old.name;
    setCert(old.cert);
    return *this;
}

Ssl::ValidateCertificateResponse::CertItem::~CertItem()
{
    if (cert)
        X509_free(cert);
}

void
Ssl::ValidateCertificateResponse::CertItem::setCert(X509 *aCert)
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

