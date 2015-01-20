## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Only build this helper on Windows
AC_CHECK_HEADERS([w32api/windows.h windows.h],[BUILD_HELPER="SSPI"])
