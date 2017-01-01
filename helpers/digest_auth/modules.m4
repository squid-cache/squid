## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_auth_digest list containing double entries.

#not specified. Inherit global
if test "x$enable_auth_digest" = "x"; then
    enable_auth_digest=$enable_auth
fi
#conflicts with global
if test "x$enable_auth_digest" != "xno" -a "x$enable_auth" = "xno" ; then
    AC_MSG_ERROR([Digest auth requested but auth disabled])
fi
#define list of modules to build
auto_auth_digest_modules=no
if test "x$enable_auth_digest" = "xyes" ; then
    SQUID_LOOK_FOR_MODULES([$srcdir/helpers/digest_auth],[enable_auth_digest])
  auto_auth_digest_modules=yes
fi
#handle the "none" special case
if test "x$enable_auth_digest" = "xnone" ; then
    enable_auth_digest=""
fi

DIGEST_AUTH_HELPERS=""
enable_auth_digest="`echo $enable_auth_digest| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_auth_digest" != "xno" ; then
    AUTH_MODULES="$AUTH_MODULES digest"
    AC_DEFINE([HAVE_AUTH_MODULE_DIGEST],1,[Digest auth module is built])
    for helper in $enable_auth_digest; do
      dir="$srcdir/helpers/digest_auth/$helper"

      # modules converted to autoconf macros already
      # NP: we only need this list because m4_include() does not accept variables
      if test "x$helper" = "xLDAP" ; then
        m4_include([helpers/digest_auth/LDAP/required.m4])

      elif test "x$helper" = "xeDirectory" ; then
        m4_include([helpers/digest_auth/eDirectory/required.m4])

      elif test "x$helper" = "xfile" ; then
        m4_include([helpers/digest_auth/file/required.m4])

      # modules not yet converted to autoconf macros (or third party drop-in's)
      elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
        BUILD_HELPER="$helper"
      fi

      if test -d "$srcdir/helpers/digest_auth/$helper"; then
        if test "$BUILD_HELPER" != "$helper"; then
          if test "x$auto_auth_digest_modules" = "xyes"; then
            AC_MSG_NOTICE([Digest auth helper $helper ... found but cannot be built])
          else
            AC_MSG_ERROR([Digest auth helper $helper ... found but cannot be built])
          fi
        else
          DIGEST_AUTH_HELPERS="$DIGEST_AUTH_HELPERS $BUILD_HELPER"
        fi
      else
        AC_MSG_ERROR([Digest auth helper $helper ... not found])
      fi
    done
fi
AC_MSG_NOTICE([Digest auth helpers to be built: $DIGEST_AUTH_HELPERS])
AM_CONDITIONAL(ENABLE_AUTH_DIGEST, test "x$enable_auth_digest" != "xno")
AC_SUBST(DIGEST_AUTH_HELPERS)
