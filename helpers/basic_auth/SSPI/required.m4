#
# Only build this helper on Windows
#
# FIXME: do we really need the mingw check anymore?
if test "$squid_host_os" = "mingw"; then
	BUILD_HELPER="SSPI"
fi
AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER="SSPI"])
