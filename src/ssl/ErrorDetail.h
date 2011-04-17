#ifndef _SQUID_SSL_ERROR_DETAIL_H
#define _SQUID_SSL_ERROR_DETAIL_H

#include "ssl_support.h"
#include "ssl/gadgets.h"
#include "SquidString.h"

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

// Custom SSL errors; assumes all official errors are positive
#define SQUID_X509_V_ERR_DOMAIN_MISMATCH -1
// All SSL errors range: from smallest (negative) custom to largest SSL error
#define SQUID_SSL_ERROR_MIN SQUID_X509_V_ERR_DOMAIN_MISMATCH
#define SQUID_SSL_ERROR_MAX INT_MAX

namespace Ssl
{
/// Squid defined error code (<0),  an error code returned by SSL X509 api, or SSL_ERROR_NONE
typedef int ssl_error_t;

/**
   \ingroup ServerProtocolSSLAPI
 * The ssl_error_t representation of the error described by "name".
 */
ssl_error_t parseErrorString(const char *name);

/**
   \ingroup ServerProtocolSSLAPI
 * The string representation of the SSL error "value"
 */
const char *getErrorName(ssl_error_t value);

/**
   \ingroup ServerProtocolSSLAPI
 * Used to pass SSL error details to the error pages returned to the
 * end user.
 */
class ErrorDetail
{
public:
    ErrorDetail(ssl_error_t err_no, X509 *cert);
    ErrorDetail(ErrorDetail const &);
    const String &toString() const;  ///< An error detail string to embed in squid error pages

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

    int convert(const char *code, const char **value) const;
    void buildDetail() const;

    mutable String errDetailStr; ///< Caches the error detail message
    ssl_error_t error_no;   ///< The error code
    X509_Pointer peer_cert; ///< A pointer to the peer certificate
};

}//namespace Ssl
#endif
