## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

if test "x$PERL" != "x"; then
  BUILD_HELPER="fake"
fi
if test "x$POD2MAN" = "x"; then
  AC_MSG_WARN([pod2man not found. security_fake_certverify man(8) page will not be built])
fi

