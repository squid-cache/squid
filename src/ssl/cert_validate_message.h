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
        ErrorItem(): id(0), error_no(SSL_ERROR_NONE), cert(NULL) {}
        ErrorItem(const ErrorItem &);
        ~ErrorItem();
        ErrorItem & operator = (const ErrorItem &);
        void setCert(X509 *);
        void clear();
        int id; ///<  The id of the error
        ssl_error_t error_no; ///< The SSL error code
        std::string error_reason; ///< A string describing the error
        X509 *cert; ///< The broken certificate
    };

    typedef std::vector<ErrorItem> Errors;

    ValidateCertificateResponse() {}
    /// Search in errors list for an error with id=errorId
    /// If know found a new ErrorItem added with the given id;
    ErrorItem &getError(int errorId);
    Errors errors; ///< The list of parsed errors
};

class CertValidateMessage: public CrtdMessage {
private:
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
public:
    CertValidateMessage(): CrtdMessage() {}
    void composeRequest(ValidateCertificate const &vcert);
    bool parseResponse(ValidateCertificateResponse &resp, STACK_OF(X509) *peerCerts, std::string &error);
    X509 *getCertByName(std::vector<CertItem> const &, std::string const & name); ///< search in a list of CertItems for a certificate

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
