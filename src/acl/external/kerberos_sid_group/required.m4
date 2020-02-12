## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_PATH_PROG(LDAPSEARCH, ldapsearch)
if test "x$LDAPSEARCH" = "x"; then
  AC_MSG_WARN([ldapsearch not found in default location. ext_kerberos_sid_group_acl may not work on this machine])
fi

# allow script install anyway when perl is present
if test "x$PERL" != "x"; then
  BUILD_HELPER="kerberos_sid_group"
fi
if test "x$POD2MAN" = "x"; then
  AC_MSG_WARN([pod2man not found. ext_kerberos_sid_group_acl man(8) page will not be built])
fi

