## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_auth_ntlm list containing double entries.

#not specified. Inherit global
if test "x$enable_auth_ntlm" = "x"; then
    enable_auth_ntlm=$enable_auth
fi
#conflicts with global
if test "x$enable_auth_ntlm" != "xno" -a "x$enable_auth" = "xno" ; then
    AC_MSG_ERROR([NTLM auth requested but auth disabled])
fi
#define list of modules to build
auto_auth_ntlm_modules=no
if test "x$enable_auth_ntlm" = "xyes" ; then
    SQUID_LOOK_FOR_MODULES([$srcdir/helpers/ntlm_auth],[enable_auth_ntlm])
  auto_auth_ntlm_modules=yes
fi
#handle the "none" special case
if test "x$enable_auth_ntlm" = "xnone" ; then
    enable_auth_ntlm=""
fi

NTLM_AUTH_HELPERS=""
#enable_auth_ntlm contains either "no" or the list of modules to be built
enable_auth_ntlm="`echo $enable_auth_ntlm| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_auth_ntlm" != "xno" ; then
    AUTH_MODULES="$AUTH_MODULES ntlm"
    AC_DEFINE([HAVE_AUTH_MODULE_NTLM],1,[NTLM auth module is built])
    for helper in $enable_auth_ntlm; do
      dir="$srcdir/helpers/ntlm_auth/$helper"

      # modules converted to autoconf macros already
      # NP: we only need this list because m4_include() does not accept variables
      if test "x$helper" = "xfake" ; then
        m4_include([helpers/ntlm_auth/fake/required.m4])

      elif test "x$helper" = "xSSPI" ; then
        m4_include([helpers/ntlm_auth/SSPI/required.m4])

      elif test "x$helper" = "xsmb_lm" ; then
        m4_include([helpers/ntlm_auth/smb_lm/required.m4])

      # modules not yet converted to autoconf macros (or third party drop-in's)
      elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
        BUILD_HELPER="$helper"
      fi

      if test -d "$srcdir/helpers/ntlm_auth/$helper"; then
        if test "$BUILD_HELPER" != "$helper"; then
          if test "x$auto_auth_ntlm_modules" = "xyes"; then
            AC_MSG_NOTICE([NTLM auth helper $helper ... found but cannot be built])
          else
            AC_MSG_ERROR([NTLM auth helper $helper ... found but cannot be built])
          fi
        else
          NTLM_AUTH_HELPERS="$NTLM_AUTH_HELPERS $BUILD_HELPER"
        fi
      else
        AC_MSG_ERROR([NTLM auth helper $helper ... not found])
      fi
    done
fi
AC_MSG_NOTICE([NTLM auth helpers to be built: $NTLM_AUTH_HELPERS])
AM_CONDITIONAL(ENABLE_AUTH_NTLM, test "x$enable_auth_ntlm" != "xno")
AC_SUBST(NTLM_AUTH_HELPERS)

## NTLM requires some special Little-Endian conversion hacks
if test "x$enable_auth_ntlm" != "xno"; then
  AC_CHECK_HEADERS(machine/byte_swap.h sys/bswap.h endian.h sys/endian.h)
  AC_CHECK_FUNCS(
    bswap_16 bswap16 \
    bswap_32 bswap32 \
    htole16 __htole16 \
    htole32 __htole32 \
    le16toh __le16toh \
    le32toh __le32toh \
  )
fi
