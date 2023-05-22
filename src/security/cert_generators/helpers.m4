## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

SECURITY_CERTGEN_HELPERS=""
SQUID_HELPER_FEATURE_CHECK([security_cert_generators],[yes],[security/cert_generators],[
  # NP: we only need this list because m4_include() does not accept variables
  SQUID_CHECK_HELPER([file],[security/cert_generators])
])
SECURITY_CERTGEN_HELPERS=$squid_cv_BUILD_HELPERS
AC_SUBST(SECURITY_CERTGEN_HELPERS)

# XXX: Enabling the interface in Squid still requires separate option
AC_ARG_ENABLE(ssl-crtd,
  AS_HELP_STRING([--enable-ssl-crtd],
                 [Prevent Squid from directly generating TLS/SSL private key
                  and certificate. Instead enables the certificate generator
                  processes.]), [
  SQUID_YESNO([$enableval],[--enable-ssl-crtd])
])
AS_IF([test "x$enable_ssl_crtd" = "xyes" -a "x$with_openssl" = "xno"],[
  AC_MSG_ERROR([You need TLS gatewaying support to enable ssl-crtd feature. Try to use --with-openssl.])
])
SQUID_DEFINE_BOOL(USE_SSL_CRTD, ${enable_ssl_crtd:=no},[Use ssl-crtd daemon])
