#
# The shell script helper require smbclient to be in the environment PATH.
# We can install anyway, but warn if smbclient not found already
#
AC_PATH_PROG(SMBCLIENT, smbclient)
if test "x$SMBCLIENT" = "x"; then
  AC_MSG_WARN([Samba smbclient not found in default location. basic_smb_auth may not work on this machine])
fi
# allow script install anyway.
BUILD_HELPER="SMB"
