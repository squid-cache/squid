#
# DONT build this helper on Windows
#
# XXX: do we really need the mingw check?
if test "$squid_host_os" != "mingw"; then
  BUILD_HELPER="smb_lm"
  AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER=""])
fi
