## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$enable_auth" != "xno"],[
  BEARER_AUTH_HELPERS=""
  SQUID_HELPER_FEATURE_CHECK([auth_bearer],[$enable_auth],[auth/bearer],[
    :
    # No helpers bundled yet.
    # See other auth helpers.m4 files for how to construct this list.
  ])

  BEARER_AUTH_HELPERS=$squid_cv_BUILD_HELPERS
  AUTH_MODULES="$AUTH_MODULES bearer"
  AC_DEFINE([HAVE_AUTH_MODULE_BEARER],1,[Bearer auth module is built])
])
AM_CONDITIONAL(ENABLE_AUTH_BEARER, test "x$enable_auth_bearer" != "xno")
AC_SUBST(BEARER_AUTH_HELPERS)
