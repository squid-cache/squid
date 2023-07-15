## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

SECURITY_CERTV_HELPERS=""
SQUID_HELPER_FEATURE_CHECK([security_cert_validators],[yes],[security/cert_validators],[
  # NP: we only need this list because m4_include() does not accept variables
  SQUID_CHECK_HELPER([fake],[security/cert_validators])
])
SECURITY_CERTV_HELPERS=$squid_cv_BUILD_HELPERS
AC_SUBST(SECURITY_CERTV_HELPERS)
