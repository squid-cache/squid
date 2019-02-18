## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_auth_negotiate list containing double entries.

#not specified. Inherit global
if test "x$enable_auth_negotiate" = "x"; then
    enable_auth_negotiate=$enable_auth
fi
#conflicts with global
if test "x$enable_auth_negotiate" != "xno" -a "x$enable_auth" = "xno" ; then
  AC_MSG_ERROR([Negotiate auth requested but auth disabled])
fi
#define list of modules to build
auto_auth_negotiate_modules=no
if test "x$enable_auth_negotiate" = "xyes" ; then
  SQUID_LOOK_FOR_MODULES([$srcdir/src/auth/negotiate],[enable_auth_negotiate])
  auto_auth_negotiate_modules=yes
fi
#handle the "none" special case
if test "x$enable_auth_negotiate" = "xnone" ; then
    enable_auth_negotiate=""
fi

NEGOTIATE_AUTH_HELPERS=""
enable_auth_negotiate="`echo $enable_auth_negotiate| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_auth_negotiate" != "xno" ; then
    AUTH_MODULES="$AUTH_MODULES negotiate"
    AC_DEFINE([HAVE_AUTH_MODULE_NEGOTIATE],1,[Negotiate auth module is built])
    for helper in $enable_auth_negotiate; do
      dir="$srcdir/src/auth/negotiate/$helper"

      # modules converted to autoconf macros already
      # NP: we only need this list because m4_include() does not accept variables
      if test "x$helper" = "xSSPI" ; then
        m4_include([src/auth/negotiate/SSPI/required.m4])

      elif test "x$helper" = "xkerberos" ; then
        m4_include([src/auth/negotiate/kerberos/required.m4])

      elif test "x$helper" = "xwrapper" ; then
        m4_include([src/auth/negotiate/wrapper/required.m4])

      # modules not yet converted to autoconf macros (or third party drop-in's)
      elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
        BUILD_HELPER="$helper"
      fi

      if test -d "$srcdir/src/auth/negotiate/$helper"; then
        if test "$BUILD_HELPER" != "$helper"; then
          if test "x$auto_auth_negotiate_modules" = "xyes"; then
            AC_MSG_NOTICE([Negotiate auth helper $helper ... found but cannot be built])
          else
            AC_MSG_ERROR([Negotiate auth helper $helper ... found but cannot be built])
          fi
        else
          NEGOTIATE_AUTH_HELPERS="$NEGOTIATE_AUTH_HELPERS $BUILD_HELPER"
        fi
      else
        AC_MSG_ERROR([Negotiate auth helper $helper ... not found])
      fi
    done
fi

AC_MSG_NOTICE([Negotiate auth helpers to be built: $NEGOTIATE_AUTH_HELPERS])
AM_CONDITIONAL(ENABLE_AUTH_NEGOTIATE, test "x$enable_auth_negotiate" != "xno")
AC_SUBST(NEGOTIATE_AUTH_HELPERS)
