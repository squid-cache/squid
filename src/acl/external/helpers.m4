## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

EXTERNAL_ACL_HELPERS=""
SQUID_HELPER_FEATURE_CHECK([external_acl_helpers],[yes],[acl/external],[
  # NP: we only need this list because m4_include() does not accept variables
  SQUID_CHECK_HELPER([AD_group],[acl/external])
  SQUID_CHECK_HELPER([LDAP_group],[acl/external])
  SQUID_CHECK_HELPER([LM_group],[acl/external])
  SQUID_CHECK_HELPER([delayer],[acl/external])
  SQUID_CHECK_HELPER([SQL_session],[acl/external])
  SQUID_CHECK_HELPER([eDirectory_userip],[acl/external])
  SQUID_CHECK_HELPER([file_userip],[acl/external])
  SQUID_CHECK_HELPER([kerberos_ldap_group],[acl/external])
  SQUID_CHECK_HELPER([kerberos_sid_group],[acl/external])
  SQUID_CHECK_HELPER([session],[acl/external])
  SQUID_CHECK_HELPER([time_quota],[acl/external])
  SQUID_CHECK_HELPER([unix_group],[acl/external])
  SQUID_CHECK_HELPER([wbinfo_group],[acl/external])
])
EXTERNAL_ACL_HELPERS=$squid_cv_BUILD_HELPERS
AC_SUBST(EXTERNAL_ACL_HELPERS)
