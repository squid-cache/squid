## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$enable_auth" != "xno"],[
  NEGOTIATE_AUTH_HELPERS=""
  SQUID_HELPER_FEATURE_CHECK([auth_negotiate],[$enable_auth],[auth/negotiate],[
    # NP: we only need this list because m4_include() does not accept variables
    SQUID_CHECK_HELPER([SSPI],[auth/negotiate])
    SQUID_CHECK_HELPER([kerberos],[auth/negotiate])
    SQUID_CHECK_HELPER([wrapper],[auth/negotiate])
  ])
  NEGOTIATE_AUTH_HELPERS=$squid_cv_BUILD_HELPERS
  AUTH_MODULES="$AUTH_MODULES negotiate"
  AC_DEFINE([HAVE_AUTH_MODULE_NEGOTIATE],1,[Negotiate auth module is built])
])
AM_CONDITIONAL(ENABLE_AUTH_NEGOTIATE, test "x$enable_auth_negotiate" != "xno")
AC_SUBST(NEGOTIATE_AUTH_HELPERS)
