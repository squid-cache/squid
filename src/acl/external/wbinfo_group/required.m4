## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

#
# The shell script helper requires wbinfo to be in the environment PATH.
# We can install anyway, but warn if the tool is missing
#
AC_PATH_PROG(WBINFO, wbinfo)
if test "x$WBINFO" = "x"; then
  AC_MSG_WARN([Samba wbinfo not found in default location. ext_wbinfo_group_acl may not work on this machine])
fi

# allow script install anyway when perl is present
if test "x$PERL" != "x"; then
  BUILD_HELPER="wbinfo_group"
fi
if test "x$POD2MAN" = "x"; then
  AC_MSG_WARN([pod2man not found. ext_wbinfo_group_acl man(8) page will not be built])
fi

