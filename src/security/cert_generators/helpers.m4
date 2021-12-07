## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# TODO: de-duplicate $enable_security_cert_generators list containing double entries.

#define list of modules to build
auto_security_modules=no
if test "x${enable_security_cert_generators:=yes}" = "xyes" ; then
  SQUID_LOOK_FOR_MODULES([$srcdir/src/security/cert_generators],[enable_security_cert_generators])
  auto_security_certgen_modules=yes
fi

enable_security_cert_generators="`echo $enable_security_cert_generators| sed -e 's/,/ /g;s/  */ /g'`"
AC_MSG_NOTICE([Security certificate generator helper candidates: $enable_security_cert_generators])
SECURITY_CERTGEN_HELPERS=""
if test "x$enable_security_cert_generators" != "xno" ; then
  for helper in $enable_security_cert_generators; do
    dir="$srcdir/src/security/cert_generators/$helper"

    # modules converted to autoconf macros already
    # NP: we only need this list because m4_include() does not accept variables
    if test "x$helper" = "xfile" ; then
      m4_include([src/security/cert_generators/file/required.m4])

    # modules not yet converted to autoconf macros (or third party drop-in's)
    elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
      BUILD_HELPER="$helper"
    fi

    if test -d "$srcdir/src/security/cert_generators/$helper"; then
      if test "$BUILD_HELPER" != "$helper"; then
        if test "x$auto_security_certgen_modules" = "xyes"; then
          AC_MSG_NOTICE([Security certificate generator helper $helper ... found but cannot be built])
        else
          AC_MSG_ERROR([Security certificate generator helper $helper ... found but cannot be built])
        fi
      else
        SECURITY_CERTGEN_HELPERS="$SECURITY_CERTGEN_HELPERS $BUILD_HELPER"
      fi
    else
      AC_MSG_ERROR([Security certificate generator helper $helper ... not found])
    fi
  done
fi
AC_MSG_NOTICE([Security certificate generator helpers to be built: $SECURITY_CERTGEN_HELPERS])
AC_SUBST(SECURITY_CERTGEN_HELPERS)

# XXX: Enabling the interface in Squid still requires separate option
AC_ARG_ENABLE(ssl-crtd,
  AC_HELP_STRING([--enable-ssl-crtd],
                 [Prevent Squid from directly generating TLS/SSL private key
                  and certificate. Instead enables the certificate generator
                  processes.]), [
  SQUID_YESNO([$enableval],
  [unrecogized argument to --enable-ssl-crtd: $enableval])
])
if test "x$enable_ssl_crtd" = "xyes" -a "x$with_openssl" = "xno" ; then
  AC_MSG_ERROR([You need ssl gatewaying support to enable ssl-crtd feature. Try to use --with-openssl.])
fi
SQUID_DEFINE_BOOL(USE_SSL_CRTD, ${enable_ssl_crtd:=no},[Use ssl-crtd daemon])
