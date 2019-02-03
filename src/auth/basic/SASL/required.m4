## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

SQUID_CHECK_SASL

# on success, add to the built modules list
if test "x$squid_cv_check_sasl" = "xyes"; then
  BUILD_HELPER="SASL"
fi
