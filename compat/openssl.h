/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* OpenSSL API changed dramatically between 1.0.2 and 1.1.0, and
 * compatibility was broken.  Most of the structures became opaque,
 * and access functions were created.  There's no (safe) way to
 * access the struct members any more, so the solution is to use
 * the new API in the main code, and add the functions for older
 * versions in compat/openssl.h.
 * Once all the supported library versions use the new API, the shim
 * can be dropped.
 */

#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#if !USE_OPENSSL
#error compat/openssl.h depends on USE_OPENSSL
#endif

#if HAVE_OPENSSL_ASN1_H
#include <openssl/asn1.h>
#endif
#if HAVE_OPENSSL_BIO_H
#include <openssl/bio.h>
#endif
#if HAVE_OPENSSL_DH_H
#include <openssl/dh.h>
#endif
#if HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif
#if HAVE_OPENSSL_LHASH_H
#include <openssl/lhash.h>
#endif
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif
#if HAVE_OPENSSL_X509_H
#include <openssl/x509.h>
#endif

extern "C" {

#if !HAVE_LIBCRYPTO_ASN1_STRING_GET0_DATA
    inline const unsigned char *
    ASN1_STRING_get0_data(const ASN1_STRING *x)
    {
        return x->data;
    }
#endif

#if !HAVE_LIBCRYPTO_BIO_GET_DATA
    inline void *
    BIO_get_data(BIO *table)
    {
        return table->ptr;
    }

    inline void
    BIO_set_data(BIO *table, void *data)
    {
        table->ptr = data;
    }

    inline void
    BIO_set_init(BIO *table, int init)
    {
        table->init = init;
    }
#endif

#if !HAVE_LIBCRYPTO_BIO_GET_INIT
    inline int
    BIO_get_init(BIO *table)
    {
        return table->init;
    }
#endif

#if !HAVE_LIBCRYPTO_DH_UP_REF // OpenSSL 1.1 API
#if defined(CRYPTO_LOCK_DH) // OpenSSL 1.0 API
    inline int
    DH_up_ref(DH *t)
    {
        if (t && (CRYPTO_add(&t->references, 1, CRYPTO_LOCK_DH) > 1))
            return 1;
        return 0;
    }
#else
#error missing both OpenSSL API features DH_up_ref (v1.1) and CRYPTO_LOCK_DH (v1.0)
#endif /* OpenSSL 1.0 CRYPTO_LOCK_DH */
#endif /* OpenSSL 1.1 DH_up_ref */

#if !HAVE_LIBCRYPTO_EVP_PKEY_GET0_RSA
    inline RSA *
    EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
    {
        if (pkey->type != EVP_PKEY_RSA)
            return nullptr;
        return pkey->pkey.rsa;
    }
#endif

#if !HAVE_LIBCRYPTO_EVP_PKEY_UP_REF
#if defined(CRYPTO_LOCK_EVP_PKEY) // OpenSSL 1.0
    inline int
    EVP_PKEY_up_ref(EVP_PKEY *t)
    {
        if (t && (CRYPTO_add(&t->references, 1, CRYPTO_LOCK_EVP_PKEY)) > 1)
            return 1;
        return 0;
    }

#else
#error missing both OpenSSL API features EVP_PKEY_up_ref (v1.1) and CRYPTO_LOCK_EVP_PKEY (v1.0)
#endif /* OpenSSL 1.0 CRYPTO_LOCK_EVP_PKEY */
#endif /* OpenSSL 1.1 EVP_PKEY_up_ref */

#if !HAVE_LIBCRYPTO_OPENSSL_LH_STRHASH
#define OPENSSL_LH_delete lh_delete
#define OPENSSL_LH_strhash lh_strhash
#endif

#if !defined OPENSSL_VERSION
#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version SSLeay_version
#endif

#if !HAVE_LIBSSL_SSL_CIPHER_FIND
    inline const SSL_CIPHER *
    SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)
    {
        return ssl->method->get_cipher_by_char(ptr);
    }
#endif

#if !HAVE_LIBSSL_SSL_SESSION_GET_ID
    inline const unsigned char *
    SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len)
    {
        if (len)
            *len = s->session_id_length;
        return s->session_id;
    }
#endif

#if !HAVE_OPENSSL_TLS_CLIENT_METHOD
#define TLS_client_method SSLv23_client_method
#endif

#if !HAVE_OPENSSL_TLS_SERVER_METHOD
#define TLS_server_method SSLv23_server_method
#endif

#if !HAVE_LIBCRYPTO_X509_CRL_UP_REF // OpenSSL 1.1 API
#if defined(CRYPTO_LOCK_X509_CRL) // OpenSSL 1.0 API
    inline int
    X509_CRL_up_ref(X509_CRL *t)
    {
        if (t && (CRYPTO_add(&t->references, 1, CRYPTO_LOCK_X509_CRL) > 1))
            return 1;
        return 0;
    }
#else
#error missing both OpenSSL API features X509_up_ref (v1.1) and CRYPTO_LOCK_X509 (v1.0)
#endif /* CRYPTO_LOCK_X509_CRL */
#endif /* X509_CRL_up_ref */

#if !HAVE_LIBCRYPTO_X509_GET0_SIGNATURE
    inline void
    X509_get0_signature(ASN1_BIT_STRING **psig, X509_ALGOR **palg, const X509 *x)
    {
        if (psig)
            *psig = (ASN1_BIT_STRING *)&x->signature;
        if (palg)
            *palg = (X509_ALGOR *)&x->sig_alg;
    }
#endif

#if !HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_CERT
    inline X509 *
    X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx)
    {
        return ctx->cert;
    }
#endif

#if !HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_UNTRUSTED
    inline STACK_OF(X509) *
    X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *ctx)
    {
        return ctx->untrusted;
    }

/// Note that all of the calls in this next group were renamed, or had the new
/// name added at the same time as X509_STORE_CTX_get0_untrusted was implemented,
/// in all supported OpenSSL-compatible libraries
#define X509_STORE_CTX_set0_untrusted X509_STORE_CTX_set_chain
#define X509_getm_notAfter X509_get_notAfter
#define X509_getm_notBefore X509_get_notBefore
#define X509_set1_notAfter X509_set_notAfter
#define X509_set1_notBefore X509_set_notBefore
#endif /* !HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_UNTRUSTED */

#if !HAVE_LIBCRYPTO_X509_UP_REF // OpenSSL 1.1 API
#if defined(CRYPTO_LOCK_X509) // OpenSSL 1.0 API
    inline int
    X509_up_ref(X509 *t)
    {
        if (t && (CRYPTO_add(&t->references, 1, CRYPTO_LOCK_X509)) > 1)
            return 1;
        return 0;
    }
#else
#error missing both OpenSSL API features X509_up_ref (v1.1) and CRYPTO_LOCK_X509 (v1.0)
#endif /* CRYPTO_LOCK_X509 */
#endif /* X509_up_ref */

#if !HAVE_LIBCRYPTO_X509_VERIFY_PARAM_GET_DEPTH
    inline int
    X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param)
    {
        return param->depth;
    }
#endif

} /* extern "C" */

inline void
SQUID_OPENSSL_init_ssl(void)
{
#if HAVE_LIBSSL_OPENSSL_INIT_SSL
    // OpenSSL will properly auto-initialize itself (in Squid context).
    // No explicit initialization is required.
    //OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
#else
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
#endif
}

#endif /* OPENSSL_COMPAT_H */

