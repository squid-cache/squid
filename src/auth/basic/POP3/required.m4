## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$PERL" != "x"],[BUILD_HELPER="POP3"])
AS_IF([test "x$POD2MAN" = "x"],[
  AC_MSG_WARN([pod2man not found. basic_pop3_auth man(8) page will not be built])
])

