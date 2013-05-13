#
# DONT build this helper on Windows
#
BUILD_HELPER="MSNT"
AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER=""])
