## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AS_IF([test "x$LIBLDAP_LIBS" != "x" -a "x$squid_host_os" != "xmingw"],[
  BUILD_HELPER="eDirectory_userip"
])
