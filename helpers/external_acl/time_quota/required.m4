AC_CHECK_HEADERS([db_185.h],[BUILD_HELPER="time_quota"])
AC_EGREP_HEADER(/usr/include/db.h,dbopen,[BUILD_HELPER="time_quota"])
