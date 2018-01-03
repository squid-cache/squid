## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_url_rewrite_helpers list containing double entries.

#define list of modules to build
auto_urlrewrite_modules=no
if test "x${enable_url_rewrite_helpers:=yes}" = "xyes" ; then
    SQUID_LOOK_FOR_MODULES([$srcdir/src/http/url_rewriters],[enable_url_rewrite_helpers])
  auto_urlrewrite_modules=yes
fi

enable_url_rewrite_helpers="`echo $enable_url_rewrite_helpers| sed -e 's/,/ /g;s/  */ /g'`"
AC_MSG_NOTICE([URL rewrite helper candidates: $enable_url_rewrite_helpers])
URL_REWRITE_HELPERS=""
if test "x$enable_url_rewrite_helpers" != "xno" ; then
  for helper in $enable_url_rewrite_helpers; do
    dir="$srcdir/src/http/url_rewriters/$helper"

    # modules converted to autoconf macros already
    # NP: we only need this list because m4_include() does not accept variables
    if test "x$helper" = "xfake" ; then
      m4_include([src/http/url_rewriters/fake/required.m4])

    elif test "x$helper" = "xLFS" ; then
      m4_include([src/http/url_rewriters/LFS/required.m4])

    # modules not yet converted to autoconf macros (or third party drop-in's)
    elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
      BUILD_HELPER="$helper"
    fi

    if test -d "$srcdir/src/http/url_rewriters/$helper"; then
      if test "$BUILD_HELPER" != "$helper"; then
        if test "x$auto_urlrewrite_modules" = "xyes"; then
          AC_MSG_NOTICE([URL rewrite helper $helper ... found but cannot be built])
        else
          AC_MSG_ERROR([URL rewrite helper $helper ... found but cannot be built])
        fi
      else
        URL_REWRITE_HELPERS="$URL_REWRITE_HELPERS $BUILD_HELPER"
      fi
    else
      AC_MSG_ERROR([URL rewrite helper $helper ... not found])
    fi
  done
fi
AC_MSG_NOTICE([URL rewrite helpers to be built: $URL_REWRITE_HELPERS])
AC_SUBST(URL_REWRITE_HELPERS)
