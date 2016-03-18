## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl checks whether dbopen needs -ldb to be added to libs
dnl sets ac_cv_dbopen_libdb to either "yes" or "no"

AC_DEFUN([SQUID_CHECK_DBOPEN_NEEDS_LIBDB],[
  AC_CACHE_CHECK(if dbopen needs -ldb,ac_cv_dbopen_libdb, [
    SQUID_STATE_SAVE(dbopen_libdb)
    LIBS="$LIBS -ldb"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_DB_185_H
#include <db_185.h>
#elif HAVE_DB_H
#include <db.h>
#endif]], 
[[dbopen("", 0, 0, DB_HASH, (void *)0L)]])],
    [ac_cv_dbopen_libdb="yes"],
    [ac_cv_dbopen_libdb="no"])
    SQUID_STATE_ROLLBACK(dbopen_libdb)
  ])
])


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
    SSLeay_add_ssl_algorithms();
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
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
    SSLeay_add_ssl_algorithms();
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
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
]
)

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
    ])
  ],
  [
   AC_DEFINE(SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK, 1)
   AC_MSG_RESULT([yes])
  ],
  [
   AC_MSG_RESULT([no])
  ],
  [])

SQUID_STATE_ROLLBACK(check_openSSL_overwrite_hack)
]
)
