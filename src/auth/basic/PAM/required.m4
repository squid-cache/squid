## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_CHECK_HEADERS([security/pam_appl.h],[
  BUILD_HELPER="PAM"
  CHECK_STRUCT_PAM_CONV
])
