AC_CHECK_HEADERS([db_185.h],[BUILD_HELPER="time_quota"])
AC_EGREP_HEADER([dbopen],[/usr/include/db.h],[BUILD_HELPER="time_quota"])
