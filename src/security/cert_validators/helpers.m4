## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_security_cert_validators list containing double entries.

#define list of modules to build
auto_security_certv_modules=no
if test "x${enable_security_cert_validators:=yes}" = "xyes" ; then
  SQUID_LOOK_FOR_MODULES([$srcdir/src/security/cert_validators],[enable_security_cert_validators])
  auto_security_certv_modules=yes
fi

enable_security_cert_validators="`echo $enable_security_cert_validators| sed -e 's/,/ /g;s/  */ /g'`"
AC_MSG_NOTICE([Security certificate validator helper candidates: $enable_security_cert_validators])
SECURITY_CERTV_HELPERS=""
if test "x$enable_security_cert_validators" != "xno" ; then
  for helper in $enable_security_cert_validators; do
    dir="$srcdir/src/security/cert_validators/$helper"

    # modules converted to autoconf macros already
    # NP: we only need this list because m4_include() does not accept variables
    if test "x$helper" = "xfake" ; then
      m4_include([src/security/cert_validators/fake/required.m4])

    # modules not yet converted to autoconf macros (or third party drop-in's)
    elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
      BUILD_HELPER="$helper"
    fi

    if test -d "$srcdir/src/security/cert_validators/$helper"; then
      if test "$BUILD_HELPER" != "$helper"; then
        if test "x$auto_security_certv_modules" = "xyes"; then
          AC_MSG_NOTICE([Security certificate validator helper $helper ... found but cannot be built])
        else
          AC_MSG_ERROR([Security certificate validator helper $helper ... found but cannot be built])
        fi
      else
        SECURITY_CERTV_HELPERS="$SECURITY_CERTV_HELPERS $BUILD_HELPER"
      fi
    else
      AC_MSG_ERROR([Security certificate validator helper $helper ... not found])
    fi
  done
fi
AC_MSG_NOTICE([Security certificate validator helpers to be built: $SECURITY_CERTV_HELPERS])
AC_SUBST(SECURITY_CERTV_HELPERS)
