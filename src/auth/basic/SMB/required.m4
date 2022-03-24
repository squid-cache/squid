## Copyright (C) 1996-2022 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# The shell script helper require smbclient to be in the environment PATH.
# We can install anyway, but warn if smbclient not found already
#
AC_PATH_PROG(SMBCLIENT, smbclient)
if test "x$SMBCLIENT" = "x"; then
  AC_MSG_WARN([Samba smbclient not found in default location. basic_smb_auth may not work on this machine])
fi
# allow script install anyway.
BUILD_HELPER="SMB"
