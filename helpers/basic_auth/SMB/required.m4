#
## TODO: This can be done far better I'm sure
#
for prefix in /usr/local /opt /opt/samba /usr/local/samba /usr
do
    if [ -x ${prefix}/bin/smbclient ]; then
        BUILD_HELPER="SMB"
    fi
done
if test "x$BUILD_HELPER" = "x"; then
  AC_MSG_WARN([Samba smbclient not found in default location. basic_smb_auth may not work on this machine])
fi
# allow script install anyway.
BUILD_HELPER="SMB"
