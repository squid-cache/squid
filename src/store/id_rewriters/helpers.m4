## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

STOREID_REWRITE_HELPERS=""
SQUID_HELPER_FEATURE_CHECK([storeid_rewrite_helpers],[yes],[store/id_rewriters],[
  # NP: we only need this list because m4_include() does not accept variables
  SQUID_CHECK_HELPER([file],[store/id_rewriters])
])
STOREID_REWRITE_HELPERS=$squid_cv_BUILD_HELPERS
AC_SUBST(STOREID_REWRITE_HELPERS)
