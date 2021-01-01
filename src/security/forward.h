/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_FORWARD_H
#define SQUID_SRC_SECURITY_FORWARD_H

#include "base/CbDataList.h"
#include "security/Context.h"
#include "security/Session.h"

#if USE_GNUTLS && HAVE_GNUTLS_ABSTRACT_H
#include <gnutls/abstract.h>
#endif
#include <list>
#if USE_OPENSSL
#include "compat/openssl.h"
#if HAVE_OPENSSL_BN_H
#include <openssl/bn.h>
#endif
#if HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#if HAVE_OPENSSL_RSA_H
#include <openssl/rsa.h>
#endif
#endif /* USE_OPENSSL */
#include <unordered_set>

#if USE_OPENSSL
// Macro to be used to define the C++ wrapper functor of the sk_*_pop_free
// OpenSSL family of functions. The C++ functor is suffixed with the _free_wrapper
// extension
#define sk_dtor_wrapper(sk_object, argument_type, freefunction) \
        struct sk_object ## _free_wrapper { \
            void operator()(argument_type a) { sk_object ## _pop_free(a, freefunction); } \
        }
#endif /* USE_OPENSSL */

/* flags a SSL connection can be configured with */
#define SSL_FLAG_NO_DEFAULT_CA      (1<<0)
#define SSL_FLAG_DELAYED_AUTH       (1<<1)
#define SSL_FLAG_DONT_VERIFY_PEER   (1<<2)
#define SSL_FLAG_DONT_VERIFY_DOMAIN (1<<3)
#define SSL_FLAG_NO_SESSION_REUSE   (1<<4)
#define SSL_FLAG_VERIFY_CRL         (1<<5)
#define SSL_FLAG_VERIFY_CRL_ALL     (1<<6)

/// Network/connection security abstraction layer
namespace Security
{

class CertError;
/// Holds a list of X.509 certificate errors
typedef CbDataList<Security::CertError> CertErrors;

#if USE_OPENSSL
CtoCpp1(X509_free, X509 *)
typedef Security::LockingPointer<X509, X509_free_cpp, HardFun<int, X509 *, X509_up_ref> > CertPointer;
#elif USE_GNUTLS
typedef std::shared_ptr<struct gnutls_x509_crt_int> CertPointer;
#else
typedef std::shared_ptr<void> CertPointer;
#endif

#if USE_OPENSSL
CtoCpp1(X509_CRL_free, X509_CRL *)
typedef Security::LockingPointer<X509_CRL, X509_CRL_free_cpp, HardFun<int, X509_CRL *, X509_CRL_up_ref> > CrlPointer;
#elif USE_GNUTLS
CtoCpp1(gnutls_x509_crl_deinit, gnutls_x509_crl_t)
typedef Security::LockingPointer<struct gnutls_x509_crl_int, gnutls_x509_crl_deinit> CrlPointer;
#else
typedef void *CrlPointer;
#endif

typedef std::list<Security::CertPointer> CertList;

typedef std::list<Security::CrlPointer> CertRevokeList;

#if USE_OPENSSL
CtoCpp1(DH_free, DH *);
typedef Security::LockingPointer<DH, DH_free_cpp, HardFun<int, DH *, DH_up_ref> > DhePointer;
#else
typedef void *DhePointer;
#endif

class EncryptorAnswer;

/// Squid defined error code (<0), an error code returned by X.509 API, or SSL_ERROR_NONE
typedef int ErrorCode;

inline const char *ErrorString(const ErrorCode code) {
#if USE_OPENSSL
    return ERR_error_string(code, nullptr);
#elif USE_GNUTLS
    return gnutls_strerror(code);
#else
    return "[no TLS library]";
#endif
}

/// set of Squid defined TLS error codes
/// \note using std::unordered_set ensures values are unique, with fast lookup
typedef std::unordered_set<Security::ErrorCode> Errors;

namespace Io
{
enum Type {
#if USE_OPENSSL
    BIO_TO_CLIENT = 6000,
    BIO_TO_SERVER
#elif USE_GNUTLS
    // NP: this is odd looking but correct.
    // 'to-client' means we are a server, and vice versa.
    BIO_TO_CLIENT = GNUTLS_SERVER,
    BIO_TO_SERVER = GNUTLS_CLIENT
#else
    BIO_TO_CLIENT = 6000,
    BIO_TO_SERVER
#endif
};

} // namespace Io

class KeyData;

#if USE_OPENSSL
typedef long ParsedOptions;
#elif USE_GNUTLS
typedef std::shared_ptr<struct gnutls_priority_st> ParsedOptions;
#else
class ParsedOptions {}; // we never parse/use TLS options in this case
#endif

class PeerConnector;
class PeerOptions;

#if USE_OPENSSL
CtoCpp1(EVP_PKEY_free, EVP_PKEY *)
typedef Security::LockingPointer<EVP_PKEY, EVP_PKEY_free_cpp, HardFun<int, EVP_PKEY *, EVP_PKEY_up_ref> > PrivateKeyPointer;
#elif USE_GNUTLS
typedef std::shared_ptr<struct gnutls_x509_privkey_int> PrivateKeyPointer;
#else
typedef std::shared_ptr<void> PrivateKeyPointer;
#endif

class ServerOptions;

} // namespace Security

#endif /* SQUID_SRC_SECURITY_FORWARD_H */

