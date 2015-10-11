/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_FORWARD_H
#define SQUID_SRC_SECURITY_FORWARD_H

#include "security/Context.h"
#include "security/LockingPointer.h"
#include "security/Session.h"

#if USE_GNUTLS
#if HAVE_GNUTLS_X509_H
#include <gnutls/x509.h>
#endif
#endif
#include <list>

/* flags a SSL connection can be configured with */
#define SSL_FLAG_NO_DEFAULT_CA      (1<<0)
#define SSL_FLAG_DELAYED_AUTH       (1<<1)
#define SSL_FLAG_DONT_VERIFY_PEER   (1<<2)
#define SSL_FLAG_DONT_VERIFY_DOMAIN (1<<3)
#define SSL_FLAG_NO_SESSION_REUSE   (1<<4)
#define SSL_FLAG_VERIFY_CRL         (1<<5)
#define SSL_FLAG_VERIFY_CRL_ALL     (1<<6)

// Macro to be used to define the C++ equivalent function of an extern "C"
// function. The C++ function suffixed with the _cpp extension
#define CtoCpp1(function, argument) \
        extern "C++" inline void function ## _cpp(argument a) { \
            function(a); \
        }

#if USE_OPENSSL
// Macro to be used to define the C++ wrapper function of a sk_*_pop_free
// openssl family functions. The C++ function suffixed with the _free_wrapper
// extension
#define sk_free_wrapper(sk_object, argument, freefunction) \
        extern "C++" inline void sk_object ## _free_wrapper(argument a) { \
            sk_object ## _pop_free(a, freefunction); \
        }
#endif

/// Network/connection security abstraction layer
namespace Security
{

class EncryptorAnswer;
class PeerOptions;
class ServerOptions;

#if USE_OPENSSL
CtoCpp1(X509_free, X509 *)
typedef Security::LockingPointer<X509, X509_free_cpp, CRYPTO_LOCK_X509> CertPointer;
#elif USE_GNUTLS
CtoCpp1(gnutls_x509_crt_deinit, gnutls_x509_crt_t)
typedef Security::LockingPointer<struct gnutls_x509_crt_int, gnutls_x509_crt_deinit, -1> CertPointer;
#else
typedef void * CertPointer;
#endif

#if USE_OPENSSL
CtoCpp1(X509_CRL_free, X509_CRL *)
typedef LockingPointer<X509_CRL, X509_CRL_free_cpp, CRYPTO_LOCK_X509_CRL> CrlPointer;
#elif USE_GNUTLS
CtoCpp1(gnutls_x509_crl_deinit, gnutls_x509_crl_t)
typedef Security::LockingPointer<struct gnutls_x509_crl_int, gnutls_x509_crl_deinit, -1> CrlPointer;
#else
typedef void *CrlPointer;
#endif

typedef std::list<Security::CrlPointer> CertRevokeList;

#if USE_OPENSSL
CtoCpp1(DH_free, DH *);
typedef Security::LockingPointer<DH, DH_free_cpp, CRYPTO_LOCK_DH> DhePointer;
#else
typedef void *DhePointer;
#endif

} // namespace Security

#endif /* SQUID_SRC_SECURITY_FORWARD_H */

