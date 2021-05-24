## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# TODO: de-duplicate $enable_storeid_rewrite_helpers list containing double entries.

#define list of modules to build
auto_storeid_modules=no
if test "x${enable_storeid_rewrite_helpers:=yes}" = "xyes" ; then
    SQUID_LOOK_FOR_MODULES([$srcdir/src/store/id_rewriters],[enable_storeid_rewrite_helpers])
  auto_storeid_modules=yes
fi

enable_storeid_rewrite_helpers="`echo $enable_storeid_rewrite_helpers| sed -e 's/,/ /g;s/  */ /g'`"
AC_MSG_NOTICE([Store-ID rewrite helper candidates: $enable_storeid_rewrite_helpers])
STOREID_REWRITE_HELPERS=""
if test "x$enable_storeid_rewrite_helpers" != "xno" ; then
  for helper in $enable_storeid_rewrite_helpers; do
    dir="$srcdir/src/store/id_rewriters/$helper"

    # modules converted to autoconf macros already
    # NP: we only need this list because m4_include() does not accept variables
    if test "x$helper" = "xfile" ; then
      m4_include([src/store/id_rewriters/file/required.m4])

    # modules not yet converted to autoconf macros (or third party drop-in's)
    elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
      BUILD_HELPER="$helper"
    fi

    if test -d "$srcdir/src/store/id_rewriters/$helper"; then
      if test "$BUILD_HELPER" != "$helper"; then
        if test "x$auto_storeid_modules" = "xyes"; then
          AC_MSG_NOTICE([Store-ID rewrite helper $helper ... found but cannot be built])
        else
          AC_MSG_ERROR([Store-ID rewrite helper $helper ... found but cannot be built])
        fi
      else
        STOREID_REWRITE_HELPERS="$STOREID_REWRITE_HELPERS $BUILD_HELPER"
      fi
    else
      AC_MSG_ERROR([Store-ID rewrite helper $helper ... not found])
    fi
  done
fi
AC_MSG_NOTICE([Store-ID rewrite helpers to be built: $STOREID_REWRITE_HELPERS])
AC_SUBST(STOREID_REWRITE_HELPERS)
