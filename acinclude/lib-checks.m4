## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check whether regex works by actually compiling one
dnl sets squid_cv_regex_works to either yes or no

AC_DEFUN([SQUID_CHECK_REGEX_WORKS],[
  AC_CACHE_CHECK([if the system-supplied regex lib actually works],squid_cv_regex_works,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_REGEX_H
#include <regex.h>
#endif
]], [[
regex_t t; regcomp(&t,"",0);]])],
    [ squid_cv_regex_works=yes ],
    [ squid_cv_regex_works=no ])
  ])
])


AC_DEFUN([SQUID_CHECK_LIBIPHLPAPI],[
  AC_CACHE_CHECK([for libIpHlpApi],squid_cv_have_libiphlpapi,[
    SQUID_STATE_SAVE(iphlpapi)
    LIBS="$LIBS -liphlpapi"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
]], [[
  MIB_IPNETTABLE i;
  unsigned long isz=sizeof(i);
  GetIpNetTable(&i,&isz,FALSE);
    ]])],
    [squid_cv_have_libiphlpapi=yes
     SQUID_STATE_COMMIT(iphlpapi)],
    [squid_cv_have_libiphlpapi=no
     SQUID_STATE_ROLLBACK(iphlpapi)])
  ])
  SQUID_STATE_ROLLBACK(iphlpapi)
])

dnl Checks whether the -lssl library provides OpenSSL TLS_*_method() definitions
AC_DEFUN([SQUID_CHECK_OPENSSL_TLS_METHODS],[
  AH_TEMPLATE(HAVE_OPENSSL_TLS_METHOD, "Define to 1 if the TLS_method() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_OPENSSL_TLS_CLIENT_METHOD, "Define to 1 if the TLS_client_method() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_OPENSSL_TLS_SERVER_METHOD, "Define to 1 if the TLS_server_method() OpenSSL API function exists")
  SQUID_STATE_SAVE(check_openssl_TLS_METHODS)
  LIBS="$LIBS $SSLLIB"
  AC_CHECK_LIB(ssl, TLS_method, AC_DEFINE(HAVE_OPENSSL_TLS_METHOD, 1))
  AC_CHECK_LIB(ssl, TLS_client_method, AC_DEFINE(HAVE_OPENSSL_TLS_CLIENT_METHOD, 1))
  AC_CHECK_LIB(ssl, TLS_server_method, AC_DEFINE(HAVE_OPENSSL_TLS_SERVER_METHOD, 1))
  SQUID_STATE_ROLLBACK(check_openssl_TLS_METHODS)
])

dnl Checks whether the -lcrypto library provides various OpenSSL API functions
AC_DEFUN([SQUID_CHECK_LIBCRYPTO_API],[
  AH_TEMPLATE(HAVE_LIBCRYPTO_OPENSSL_LH_STRHASH, "Define to 1 if the OPENSSL_LH_strhash() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_EVP_PKEY_GET0_RSA, "Define to 1 if the EVP_PKEY_get0_RSA() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_BIO_METH_NEW, "Define to 1 if the BIO_meth_new() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_BIO_GET_DATA, "Define to 1 if the BIO_get_data() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_BIO_GET_INIT, "Define to 1 if the BIO_get_init() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_ASN1_STRING_GET0_DATA, "Define to 1 if the ASN1_STRING_get0_data() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_EVP_PKEY_UP_REF, "Define to 1 if the EVP_PKEY_up_ref() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_CERT, "Define to 1 if the X509_STORE_CTX_get0_cert() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_VERIFY_PARAM_GET_DEPTH, "Define to 1 if the X509_VERIFY_PARAM_get_depth() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_UNTRUSTED, "Define to 1 if the X509_STORE_CTX_get0_untrusted() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL, "Define to 1 if the X509_VERIFY_PARAM_set_auth_level() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_UP_REF, "Define to 1 if the X509_up_ref() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_CHAIN_UP_REF, "Define to 1 if the X509_chain_up_ref() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_CRL_UP_REF, "Define to 1 if the X509_CRL_up_ref() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_DH_UP_REF, "Define to 1 if the DH_up_ref() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBCRYPTO_X509_GET0_SIGNATURE, "Define to 1 if the X509_get0_signature() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_SSL_GET0_PARAM, "Define to 1 of the SSL_get0_param() OpenSSL API function exists")
  SQUID_STATE_SAVE(check_openssl_libcrypto_api)
  LIBS="$LIBS $SSLLIB"
  AC_CHECK_LIB(crypto, OPENSSL_LH_strhash, AC_DEFINE(HAVE_LIBCRYPTO_OPENSSL_LH_STRHASH, 1))
  AC_CHECK_LIB(crypto, EVP_PKEY_get0_RSA, AC_DEFINE(HAVE_LIBCRYPTO_EVP_PKEY_GET0_RSA, 1))
  AC_CHECK_LIB(crypto, BIO_meth_new, AC_DEFINE(HAVE_LIBCRYPTO_BIO_METH_NEW, 1))
  AC_CHECK_LIB(crypto, BIO_get_data, AC_DEFINE(HAVE_LIBCRYPTO_BIO_GET_DATA, 1))
  AC_CHECK_LIB(crypto, BIO_get_init, AC_DEFINE(HAVE_LIBCRYPTO_BIO_GET_INIT, 1))
  AC_CHECK_LIB(crypto, ASN1_STRING_get0_data, AC_DEFINE(HAVE_LIBCRYPTO_ASN1_STRING_GET0_DATA, 1))
  AC_CHECK_LIB(crypto, EVP_PKEY_up_ref, AC_DEFINE(HAVE_LIBCRYPTO_EVP_PKEY_UP_REF, 1))
  AC_CHECK_LIB(crypto, X509_STORE_CTX_get0_cert, AC_DEFINE(HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_CERT, 1))
  AC_CHECK_LIB(crypto, X509_VERIFY_PARAM_get_depth, AC_DEFINE(HAVE_LIBCRYPTO_X509_VERIFY_PARAM_GET_DEPTH, 1))
  AC_CHECK_LIB(crypto, X509_STORE_CTX_get0_untrusted, AC_DEFINE(HAVE_LIBCRYPTO_X509_STORE_CTX_GET0_UNTRUSTED, 1))
  AC_CHECK_LIB(crypto,  X509_VERIFY_PARAM_set_auth_level, AC_DEFINE(HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL))
  AC_CHECK_LIB(crypto, X509_up_ref, AC_DEFINE(HAVE_LIBCRYPTO_X509_UP_REF, 1))
  AC_CHECK_LIB(crypto, X509_chain_up_ref, AC_DEFINE(HAVE_LIBCRYPTO_X509_CHAIN_UP_REF, 1))
  AC_CHECK_LIB(crypto, X509_CRL_up_ref, AC_DEFINE(HAVE_LIBCRYPTO_X509_CRL_UP_REF, 1))
  AC_CHECK_LIB(crypto, DH_up_ref, AC_DEFINE(HAVE_LIBCRYPTO_DH_UP_REF, 1))
  AC_CHECK_LIB(crypto, X509_get0_signature, AC_DEFINE(HAVE_LIBCRYPTO_X509_GET0_SIGNATURE, 1), AC_DEFINE(SQUID_CONST_X509_GET0_SIGNATURE_ARGS,))
  AC_CHECK_LIB(crypto, SSL_get0_param, AC_DEFINE(HAVE_SSL_GET0_PARAM, 1))
  SQUID_STATE_ROLLBACK(check_openssl_libcrypto_api)
])

dnl Checks whether the -lssl library provides various OpenSSL API functions
AC_DEFUN([SQUID_CHECK_LIBSSL_API],[
  AH_TEMPLATE(HAVE_LIBSSL_OPENSSL_INIT_SSL, "Define to 1 if the OPENSSL_init_ssl() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBSSL_SSL_CIPHER_FIND, "Define to 1 if the SSL_CIPHER_find() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBSSL_SSL_CTX_SET_TMP_RSA_CALLBACK, "Define to 1 if the SSL_CTX_set_tmp_rsa_callback() OpenSSL API function exists")
  AH_TEMPLATE(HAVE_LIBSSL_SSL_SESSION_GET_ID, "Define to 1 if the SSL_SESSION_get_id() OpenSSL API function exists")
  SQUID_STATE_SAVE(check_openssl_libssl_api)
  LIBS="$LIBS $SSLLIB"
  AC_CHECK_LIB(ssl, OPENSSL_init_ssl, AC_DEFINE(HAVE_LIBSSL_OPENSSL_INIT_SSL, 1))
  AC_CHECK_LIB(ssl, SSL_CIPHER_find, AC_DEFINE(HAVE_LIBSSL_SSL_CIPHER_FIND, 1))
  AC_CHECK_LIB(ssl, SSL_CTX_set_tmp_rsa_callback, AC_DEFINE(HAVE_LIBSSL_SSL_CTX_SET_TMP_RSA_CALLBACK, 1))
  AC_CHECK_LIB(ssl, SSL_SESSION_get_id, AC_DEFINE(HAVE_LIBSSL_SSL_SESSION_GET_ID, 1))
  SQUID_STATE_ROLLBACK(check_openssl_libssl_api)
])

dnl Checks whether the OpenSSL SSL_get_certificate crashes squid and if a
dnl workaround can be used instead of using the SSL_get_certificate
AC_DEFUN([SQUID_CHECK_OPENSSL_GETCERTIFICATE_WORKS],[
  AH_TEMPLATE(SQUID_SSLGETCERTIFICATE_BUGGY, "Define to 1 if the SSL_get_certificate crashes squid")
  AH_TEMPLATE(SQUID_USE_SSLGETCERTIFICATE_HACK, "Define to 1 to use squid workaround for SSL_get_certificate")
  SQUID_STATE_SAVE(check_SSL_get_certificate)
  LIBS="$SSLLIB $LIBS"
  if test "x$SSLLIBDIR" != "x"; then
     LIBS="$LIBS -Wl,-rpath -Wl,$SSLLIBDIR"
  fi

  AC_MSG_CHECKING(whether the SSL_get_certificate is buggy)
  AC_RUN_IFELSE([
  AC_LANG_PROGRAM(
    [
     #include <openssl/ssl.h>
     #include <openssl/err.h>
    ],
    [
#if defined(SSLeay_add_ssl_algorithms)
    SSLeay_add_ssl_algorithms();
#endif
#if HAVE_OPENSSL_TLS_METHOD
    SSL_CTX *sslContext = SSL_CTX_new(TLS_method());
#else
    SSL_CTX *sslContext = SSL_CTX_new(SSLv23_method());
#endif
    SSL *ssl = SSL_new(sslContext);
    X509* cert = SSL_get_certificate(ssl);
    return 0;
    ])
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [
   AC_DEFINE(SQUID_SSLGETCERTIFICATE_BUGGY, 1)
   AC_MSG_RESULT([yes])
  ],
  [
   AC_DEFINE(SQUID_SSLGETCERTIFICATE_BUGGY, 0)
   AC_MSG_RESULT([cross-compile, assuming no])
  ])

  AC_MSG_CHECKING(whether the workaround for SSL_get_certificate works)
  AC_RUN_IFELSE([
  AC_LANG_PROGRAM(
    [
     #include <openssl/ssl.h>
     #include <openssl/err.h>
    ],
    [
#if defined(SSLeay_add_ssl_algorithms)
    SSLeay_add_ssl_algorithms();
#endif
#if HAVE_OPENSSL_TLS_METHOD
    SSL_CTX *sslContext = SSL_CTX_new(TLS_method());
#else
    SSL_CTX *sslContext = SSL_CTX_new(SSLv23_method());
#endif
    X509 ***pCert = (X509 ***)sslContext->cert;
    X509 *sslCtxCert = pCert && *pCert ? **pCert : (X509 *)0x1;
    if (sslCtxCert != NULL)
        return 1;
    return 0;
    ])
  ],
  [
   AC_MSG_RESULT([yes])
   AC_DEFINE(SQUID_USE_SSLGETCERTIFICATE_HACK, 1)
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [
   AC_DEFINE(SQUID_USE_SSLGETCERTIFICATE_HACK, 0)
   AC_MSG_RESULT([cross-compile, assuming no])
  ])

SQUID_STATE_ROLLBACK(check_SSL_get_certificate)
])

dnl Checks whether the  SSL_CTX_new and similar functions require
dnl a const 'SSL_METHOD *' argument
AC_DEFUN([SQUID_CHECK_OPENSSL_CONST_SSL_METHOD],[
  AH_TEMPLATE(SQUID_USE_CONST_SSL_METHOD, "Define to 1 if the SSL_CTX_new and similar openSSL API functions require 'const SSL_METHOD *'")
  SQUID_STATE_SAVE(check_const_SSL_METHOD)
  AC_MSG_CHECKING(whether SSL_CTX_new and similar openSSL API functions require 'const SSL_METHOD *'")

  AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM(
    [
     #include <openssl/ssl.h>
     #include <openssl/err.h>
    ],
    [
       const SSL_METHOD *method = NULL;
       SSL_CTX *sslContext = SSL_CTX_new(method);
       return (sslContext != NULL);
    ])
  ],
  [
   AC_DEFINE(SQUID_USE_CONST_SSL_METHOD, 1)
   AC_MSG_RESULT([yes])
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [])

SQUID_STATE_ROLLBACK(check_const_SSL_METHOD)
])

dnl Checks whether the CRYPTO_EX_DATA duplication callback for SSL_get_ex_new_index() has a const argument
AC_DEFUN([SQUID_CHECK_OPENSSL_CONST_CRYPTO_EX_DATA],[
  AH_TEMPLATE(SQUID_USE_CONST_CRYPTO_EX_DATA_DUP, "Define to 1 if the SSL_get_new_ex_index() dup callback accepts 'const CRYPTO_EX_DATA *'")
  SQUID_STATE_SAVE(check_const_CRYPTO_EX_DATA)
  AC_MSG_CHECKING(whether SSL_get_new_ex_index() dup callback accepts 'const CRYPTO_EX_DATA *'")
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <openssl/ssl.h>

int const_dup_func(CRYPTO_EX_DATA *, const CRYPTO_EX_DATA *, void *, int, long, void *) {
    return 0;
}
    ],[
return SSL_get_ex_new_index(0, (void*)"foo", NULL, &const_dup_func, NULL);
    ])
  ],[
   AC_DEFINE(SQUID_USE_CONST_CRYPTO_EX_DATA_DUP, 1)
   AC_MSG_RESULT([yes])
  ],[
   AC_MSG_RESULT([no])
  ])
  SQUID_STATE_ROLLBACK(check_const_CRYPTO_EX_DATA)
])

dnl Checks whether the callback for SSL_CTX_sess_set_get_cb() accepts a const ID argument
AC_DEFUN([SQUID_CHECK_OPENSSL_CONST_SSL_SESSION_CB_ARG],[
  AH_TEMPLATE(SQUID_USE_CONST_SSL_SESSION_CBID, "Define to 1 if the SSL_CTX_sess_set_get_cb() callback accepts a const ID argument")
  SQUID_STATE_SAVE(check_const_SSL_CTX_sess_set_get_cb)
  AC_MSG_CHECKING(whether SSL_CTX_sess_set_get_cb() callback accepts a const ID argument")
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <openssl/ssl.h>

SSL_SESSION *get_session_cb(SSL *, const unsigned char *ID, int, int *) {
    return NULL;
}
    ],[
SSL_CTX_sess_set_get_cb(NULL, get_session_cb);
return 0;
    ])
  ],[
   AC_DEFINE(SQUID_USE_CONST_SSL_SESSION_CBID, 1)
   AC_MSG_RESULT([yes])
  ],[
   AC_MSG_RESULT([no])
  ])
  SQUID_STATE_ROLLBACK(check_const_SSL_CTX_sess_set_get_cb)
])

dnl Checks whether the X509_get0_signature() has const arguments
AC_DEFUN([SQUID_CHECK_OPENSSL_CONST_X509_GET0_SIGNATURE_ARGS],[
  AH_TEMPLATE(SQUID_CONST_X509_GET0_SIGNATURE_ARGS, Define to const if X509_get0_signature() accepts const parameters; define as empty otherwise. Don't leave it undefined!)
  SQUID_STATE_SAVE(check_const_X509_get0_signature_args)
  AC_MSG_CHECKING("whether X509_get0_signature() accepts const parameters")
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <openssl/ssl.h>
    ],[
#if HAVE_LIBCRYPTO_X509_GET0_SIGNATURE
        const ASN1_BIT_STRING *sig = nullptr;
        const X509_ALGOR *sig_alg;
        X509_get0_signature(&sig, &sig_alg, nullptr);
#else
#error Missing X509_get0_signature()
#endif
    ])
  ],[
   AC_DEFINE(SQUID_CONST_X509_GET0_SIGNATURE_ARGS, const)
   AC_MSG_RESULT([yes])
  ],[
   AC_DEFINE(SQUID_CONST_X509_GET0_SIGNATURE_ARGS,)
   AC_MSG_RESULT([no])
  ])
  SQUID_STATE_ROLLBACK(check_const_X509_get0_signature_args)
])

dnl Try to handle TXT_DB related  problems:
dnl 1) The type of TXT_DB::data member changed in openSSL-1.0.1 version
dnl 2) The IMPLEMENT_LHASH_* openSSL macros in openSSL-1.0.1 and later releases is not
dnl    implemented correctly and causes type conversion errors while compiling squid

AC_DEFUN([SQUID_CHECK_OPENSSL_TXTDB],[
  AH_TEMPLATE(SQUID_SSLTXTDB_PSTRINGDATA, "Define to 1 if the TXT_DB uses OPENSSL_PSTRING data member")
  AH_TEMPLATE(SQUID_STACKOF_PSTRINGDATA_HACK, "Define to 1 to use squid workaround for buggy versions of sk_OPENSSL_PSTRING_value")
  AH_TEMPLATE(SQUID_USE_SSLLHASH_HACK, "Define to 1 to use squid workaround for openssl IMPLEMENT_LHASH_* type conversion errors")

  SQUID_STATE_SAVE(check_TXTDB)

  LIBS="$LIBS $SSLLIB"
  squid_cv_check_openssl_pstring="no"
  AC_MSG_CHECKING(whether the TXT_DB use OPENSSL_PSTRING data member)
  AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM(
    [
     #include <openssl/txt_db.h>
    ],
    [
    TXT_DB *db = NULL;
    int i = sk_OPENSSL_PSTRING_num(db->data);
    return 0;
    ])
  ],
  [
   AC_DEFINE(SQUID_SSLTXTDB_PSTRINGDATA, 1)
   AC_MSG_RESULT([yes])
   squid_cv_check_openssl_pstring="yes"
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [])

  if test x"$squid_cv_check_openssl_pstring" = "xyes"; then
     AC_MSG_CHECKING(whether the squid workaround for buggy versions of sk_OPENSSL_PSTRING_value should used)
     AC_COMPILE_IFELSE([
     AC_LANG_PROGRAM(
       [
        #include <openssl/txt_db.h>
       ],
       [
       TXT_DB *db = NULL;
       const char ** current_row = ((const char **)sk_OPENSSL_PSTRING_value(db->data, 0));
       return (current_row != NULL);
       ])
     ],
     [
      AC_MSG_RESULT([no])
     ],
     [
      AC_DEFINE(SQUID_STACKOF_PSTRINGDATA_HACK, 1)
      AC_MSG_RESULT([yes])
     ],
     [])
  fi

  AC_MSG_CHECKING(whether the workaround for OpenSSL IMPLEMENT_LHASH_  macros should used)
  AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM(
    [
     #include <openssl/txt_db.h>

     static unsigned long index_serial_hash(const char **a){}
     static int index_serial_cmp(const char **a, const char **b){}
     static IMPLEMENT_LHASH_HASH_FN(index_serial_hash,const char **)
     static IMPLEMENT_LHASH_COMP_FN(index_serial_cmp,const char **)
    ],
    [
    TXT_DB *db = NULL;
    TXT_DB_create_index(db, 1, NULL, LHASH_HASH_FN(index_serial_hash), LHASH_COMP_FN(index_serial_cmp));
    ])
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [
   AC_MSG_RESULT([yes])
   AC_DEFINE(SQUID_USE_SSLLHASH_HACK, 1)
  ],
[])

SQUID_STATE_ROLLBACK(check_TXTDB)
])

dnl Check if we can rewrite the hello message stored in an SSL object.
dnl The tests are very basic, just check if the required members exist in
dnl SSL structure.
AC_DEFUN([SQUID_CHECK_OPENSSL_HELLO_OVERWRITE_HACK],[
  AH_TEMPLATE(SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK, "Define to 1 if hello message can be overwritten in SSL struct")
  SQUID_STATE_SAVE(check_openSSL_overwrite_hack)
  AC_MSG_CHECKING(whether hello message can be overwritten in SSL struct)

  AC_COMPILE_IFELSE([
  AC_LANG_PROGRAM(
    [
     #include <openssl/ssl.h>
     #include <openssl/err.h>
     #include <assert.h>
    ],
    [
    SSL *ssl;
    char *random, *msg;
    memcpy(ssl->s3->client_random, random, SSL3_RANDOM_SIZE);
    SSL3_BUFFER *wb=&(ssl->s3->wbuf);
    assert(wb->len == 0);
    memcpy(wb->buf, msg, 0);
    assert(wb->left == 0);
    memcpy(ssl->init_buf->data, msg, 0);
    ssl->init_num = 0;
    ssl->s3->wpend_ret = 0;
    ssl->s3->wpend_tot = 0;
    SSL_CIPHER *cipher = 0;
    assert(SSL_CIPHER_get_id(cipher));
    ])
  ],
  [
   AC_MSG_RESULT([possibly; to try, set SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK macro value to 1])
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [])

SQUID_STATE_ROLLBACK(check_openSSL_overwrite_hack)
]
)
