/*
 * $Id$
 */

#ifndef SQUID_SSL_CERT_VALIDATE_MESSAGE_H
#define SQUID_SSL_CERT_VALIDATE_MESSAGE_H

#include "ssl/support.h"
#include "ssl/crtd_message.h"
#include <vector>

namespace Ssl 
{


class ValidateCertificate {
public:
    STACK_OF(X509) *peerCerts;
    Errors *errors;
    std::string domainName;
    ValidateCertificate() : peerCerts(NULL), errors(NULL) {}
};

class ValidateCertificateResponse {
public:
    class  ErrorItem{
    public:
        ErrorItem(): error_no(SSL_ERROR_NONE), cert(NULL) {}
        ErrorItem(const ErrorItem &);
        ~ErrorItem();
        ErrorItem & operator = (const ErrorItem &);
        void setCert(X509 *);
        void clear();
        ssl_error_t error_no;
        std::string error_reason;
        X509 *cert;
    };

    class CertItem {
    public:
        std::string name;
        X509 *cert;
        CertItem(): cert(NULL) {}
        CertItem(const CertItem &);
        CertItem & operator = (const CertItem &);
        ~CertItem();
        void setCert(X509 *);
    };

    std::vector<ErrorItem> errors;
    ValidateCertificateResponse() {}
    ~ValidateCertificateResponse() {/*Maybe needs to release Errors*/};
};

class CertValidateMessage: public CrtdMessage {
public:
    CertValidateMessage(): CrtdMessage() {}
    void composeRequest(ValidateCertificate const &vcert);
    bool parseResponse(ValidateCertificateResponse &resp, STACK_OF(X509) *peerCerts, std::string &error);

    /// String code for "cert_validate" messages
    static const std::string code_cert_validate;
    /// Parameter name for passing intended domain name
    static const std::string param_domain;
    /// Parameter name for passing SSL errors
    static const std::string param_error;
    /// Parameter name for passing SSL certificates
    static const std::string param_cert; 
    /// Parameter name for passing the major SSL error
    static const std::string param_error_name; 
    /// Parameter name for passing the error reason
    static const std::string param_error_reason; 
    /// Parameter name for passing the error cert ID
    static const std::string param_error_cert;
};

}//namespace Ssl
#endif // SQUID_SSL_CERT_VALIDATE_MESSAGE_H
