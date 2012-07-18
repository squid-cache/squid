#ifndef _SQUID_SSL_ERROR_DETAIL_H
#define _SQUID_SSL_ERROR_DETAIL_H

#include "err_detail_type.h"
#include "HttpRequest.h"
#include "ErrorDetailManager.h"
#include "ssl/support.h"
#include "ssl/gadgets.h"

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

namespace Ssl
{
/**
  \ingroup ServerProtocolSSLAPI
 * Converts user-friendly error "name" into an Ssl::Errors list.
 * The resulting list may have one or more elements, and needs to be
 * released by the caller.
 * This function can handle numeric error numbers as well as names.
 */
Ssl::Errors *ParseErrorString(const char *name);

/**
   \ingroup ServerProtocolSSLAPI
  * The ssl_error_t code of the error described by  "name".
  */
ssl_error_t GetErrorCode(const char *name);

/**
   \ingroup ServerProtocolSSLAPI
 * The string representation of the SSL error "value"
 */
const char *GetErrorName(ssl_error_t value);

/**
   \ingroup ServerProtocolSSLAPI
 * A short description of the SSL error "value"
 */
const char *GetErrorDescr(ssl_error_t value);

/**
   \ingroup ServerProtocolSSLAPI
 * Used to pass SSL error details to the error pages returned to the
 * end user.
 */
class ErrorDetail
{
public:
    // if broken certificate is nil, the peer certificate is broken
    ErrorDetail(ssl_error_t err_no, X509 *peer, X509 *broken);
    ErrorDetail(ErrorDetail const &);
    const String &toString() const;  ///< An error detail string to embed in squid error pages
    void useRequest(HttpRequest *aRequest) { if (aRequest != NULL) request = aRequest;}
    /// The error name to embed in squid error pages
    const char *errorName() const {return err_code();}
    /// The error no
    ssl_error_t errorNo() const {return error_no;}
    ///Sets the low-level error returned by OpenSSL ERR_get_error()
    void setLibError(unsigned long lib_err_no) {lib_error_no = lib_err_no;}
    /// the peer certificate
    X509 *peerCert() { return peer_cert.get(); }
    /// peer or intermediate certificate that failed validation
    X509 *brokenCert() {return broken_cert.get(); }
private:
    typedef const char * (ErrorDetail::*fmt_action_t)() const;
    /**
     * Holds a formating code and its conversion method
     */
    class err_frm_code
    {
    public:
        const char *code;             ///< The formating code
        fmt_action_t fmt_action; ///< A pointer to the conversion method
    };
    static err_frm_code  ErrorFormatingCodes[]; ///< The supported formating codes

    const char *subject() const;
    const char *ca_name() const;
    const char *cn() const;
    const char *notbefore() const;
    const char *notafter() const;
    const char *err_code() const;
    const char *err_descr() const;
    const char *err_lib_error() const;

    int convert(const char *code, const char **value) const;
    void buildDetail() const;

    mutable String errDetailStr; ///< Caches the error detail message
    ssl_error_t error_no;   ///< The error code
    unsigned long lib_error_no; ///< low-level error returned by OpenSSL ERR_get_error(3SSL)
    X509_Pointer peer_cert; ///< A pointer to the peer certificate
    X509_Pointer broken_cert; ///< A pointer to the broken certificate (peer or intermediate)
    mutable ErrorDetailEntry detailEntry;
    HttpRequest::Pointer request;
};

}//namespace Ssl
#endif
