## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$enable_auth" != "xno"],[
  BASIC_AUTH_HELPERS=""
  SQUID_HELPER_FEATURE_CHECK([auth_basic],[$enable_auth],[auth/basic],[
    # NP: we only need this list because m4_include() does not accept variables
    SQUID_CHECK_HELPER([DB],[auth/basic])
    SQUID_CHECK_HELPER([LDAP],[auth/basic])
    SQUID_CHECK_HELPER([NCSA],[auth/basic])
    SQUID_CHECK_HELPER([NIS],[auth/basic])
    SQUID_CHECK_HELPER([PAM],[auth/basic])
    SQUID_CHECK_HELPER([POP3],[auth/basic])
    SQUID_CHECK_HELPER([RADIUS],[auth/basic])
    SQUID_CHECK_HELPER([SASL],[auth/basic])
    SQUID_CHECK_HELPER([SMB],[auth/basic])
    SQUID_CHECK_HELPER([SMB_LM],[auth/basic])
    SQUID_CHECK_HELPER([SSPI],[auth/basic])
    SQUID_CHECK_HELPER([fake],[auth/basic])
    SQUID_CHECK_HELPER([getpwnam],[auth/basic])
  ])

  BASIC_AUTH_HELPERS=$squid_cv_BUILD_HELPERS
  AUTH_MODULES="$AUTH_MODULES basic"
  AC_DEFINE([HAVE_AUTH_MODULE_BASIC],1,[Basic auth module is built])
])
AM_CONDITIONAL(ENABLE_AUTH_BASIC, test "x$enable_auth_basic" != "xno")
AC_SUBST(BASIC_AUTH_HELPERS)
