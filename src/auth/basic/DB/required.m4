## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

if test "x$PERL" != "x"; then
  BUILD_HELPER="DB"
fi
if test "x$POD2MAN" = "x"; then
  AC_MSG_WARN([pod2man not found. basic_db_auth man(8) page will not be built])
fi

