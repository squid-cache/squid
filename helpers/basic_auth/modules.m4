## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_auth_basic list containing double entries.

#not specified. Inherit global
if test "x$enable_auth_basic" = "x"; then
    enable_auth_basic=$enable_auth
fi
#conflicts with global
if test "x$enable_auth_basic" != "xno" -a "x$enable_auth" = "xno" ; then
    AC_MSG_ERROR([Basic auth requested but auth disabled])
fi
#define list of modules to build
auto_auth_basic_modules=no
if test "x$enable_auth_basic" = "xyes" ; then
    SQUID_LOOK_FOR_MODULES([$srcdir/helpers/basic_auth],[enable_auth_basic])
  auto_auth_basic_modules=yes
fi
#handle the "none" special case
if test "x$enable_auth_basic" = "xnone" ; then
    enable_auth_basic=""
fi

BASIC_AUTH_HELPERS=""
#enable_auth_basic contains either "no" or the list of modules to be built
enable_auth_basic="`echo $enable_auth_basic| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_auth_basic" != "xno" ; then
    AUTH_MODULES="$AUTH_MODULES basic"
    AC_DEFINE([HAVE_AUTH_MODULE_BASIC],1,[Basic auth module is built])
    for helper in $enable_auth_basic; do
      dir="$srcdir/helpers/basic_auth/$helper"

      # modules converted to autoconf macros already
      # NP: we only need this list because m4_include() does not accept variables
      if test "x$helper" = "xDB" ; then
        m4_include([helpers/basic_auth/DB/required.m4])

      elif test "x$helper" = "xLDAP" ; then
        m4_include([helpers/basic_auth/LDAP/required.m4])

      elif test "x$helper" = "xMSNT-multi-domain" ; then
        m4_include([helpers/basic_auth/MSNT-multi-domain/required.m4])

      elif test "x$helper" = "xNCSA" ; then
        m4_include([helpers/basic_auth/NCSA/required.m4])

      elif test "x$helper" = "xNIS" ; then
        m4_include([helpers/basic_auth/NIS/required.m4])

      elif test "x$helper" = "xPAM" ; then
        m4_include([helpers/basic_auth/PAM/required.m4])

      elif test "x$helper" = "xPOP3" ; then
        m4_include([helpers/basic_auth/POP3/required.m4])

      elif test "x$helper" = "xRADIUS" ; then
        m4_include([helpers/basic_auth/RADIUS/required.m4])

      elif test "x$helper" = "xSASL" ; then
        m4_include([helpers/basic_auth/SASL/required.m4])

      elif test "x$helper" = "xSMB" ; then
        m4_include([helpers/basic_auth/SMB/required.m4])

      elif test "x$helper" = "xSMB_LM" ; then
        m4_include([helpers/basic_auth/SMB_LM/required.m4])

      elif test "x$helper" = "xSSPI" ; then
        m4_include([helpers/basic_auth/SSPI/required.m4])

      elif test "x$helper" = "xfake" ; then
        m4_include([helpers/basic_auth/fake/required.m4])

      elif test "x$helper" = "xgetpwnam" ; then
        m4_include([helpers/basic_auth/getpwnam/required.m4])

      # modules not yet converted to autoconf macros (or third party drop-in's)
      elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
        BUILD_HELPER="$helper"
      fi

      if test -d "$srcdir/helpers/basic_auth/$helper"; then
        if test "$BUILD_HELPER" != "$helper"; then
          if test "x$auto_auth_basic_modules" = "xyes"; then
            AC_MSG_NOTICE([Basic auth helper $helper ... found but cannot be built])
          else
            AC_MSG_ERROR([Basic auth helper $helper ... found but cannot be built])
          fi
        else
          BASIC_AUTH_HELPERS="$BASIC_AUTH_HELPERS $BUILD_HELPER"
        fi
      else
        AC_MSG_ERROR([Basic auth helper $helper ... not found])
      fi
    done
fi

AC_MSG_NOTICE([Basic auth helpers to be built: $BASIC_AUTH_HELPERS])
AM_CONDITIONAL(ENABLE_AUTH_BASIC, test "x$enable_auth_basic" != "xno")
AC_SUBST(BASIC_AUTH_HELPERS)
