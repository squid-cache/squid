#
# Only build this helper on Windows
#
AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER="LM_group"])
