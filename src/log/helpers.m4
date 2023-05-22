## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

LOG_DAEMON_HELPERS=""
SQUID_HELPER_FEATURE_CHECK([log_daemon_helpers],[yes],[log],[
  # NP: we only need this list because m4_include() does not accept variables
  SQUID_CHECK_HELPER([DB],[log])
  SQUID_CHECK_HELPER([file],[log])
])
LOG_DAEMON_HELPERS=$squid_cv_BUILD_HELPERS
AC_SUBST(LOG_DAEMON_HELPERS)
