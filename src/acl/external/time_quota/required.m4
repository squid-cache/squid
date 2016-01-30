## Copyright (C) 1996-2016 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_CHECK_HEADERS([db_185.h],[BUILD_HELPER="time_quota"])
AC_EGREP_HEADER([dbopen],[/usr/include/db.h],[BUILD_HELPER="time_quota"])
