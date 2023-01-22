## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$enable_auth" != "xno"],[
  DIGEST_AUTH_HELPERS=""
  SQUID_HELPER_FEATURE_CHECK([auth_digest],[$enable_auth],[auth/digest],[
    # NP: we only need this list because m4_include() does not accept variables
    SQUID_CHECK_HELPER([eDirectory],[auth/digest])
    SQUID_CHECK_HELPER([file],[auth/digest])
    SQUID_CHECK_HELPER([LDAP],[auth/digest])
  ])
  DIGEST_AUTH_HELPERS=$squid_cv_BUILD_HELPERS
  AUTH_MODULES="$AUTH_MODULES digest"
  AC_DEFINE([HAVE_AUTH_MODULE_DIGEST],1,[Digest auth module is built])
])
AM_CONDITIONAL(ENABLE_AUTH_DIGEST, test "x$enable_auth_digest" != "xno")
AC_SUBST(DIGEST_AUTH_HELPERS)
