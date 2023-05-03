## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# check if the Windows SSPI requirements are available and work.
# first argument is the variable containing the result
#   (will be set to "yes" or "no")
# second argument is the commands to run on success
#
AC_DEFUN([SQUID_CHECK_WIN32_SSPI],[
  AC_CACHE_CHECK([whether Windows SSPI is available],[$1],[
    AC_CHECK_HEADERS([w32api/windows.h windows.h],[
      $1=yes
      # optional headers
      AC_CHECK_HEADERS([wchar.h tchar.h])
      # required headers
      AC_CHECK_HEADERS([ntsecapi.h security.h sspi.h],,[$1=no],[
#define SECURITY_WIN32
#if HAVE_WINDOWS_H
#include <windows.h>
#elif HAVE_W32API_WINDOWS_H
#include <w32api/windows.h>
#endif
#if HAVE_NTSECAPI_H
#include <ntsecapi.h>
#endif
#if HAVE_SECURITY_H
#include <security.h>
#endif
#if HAVE_SSPI_H
#include <sspi.h>
#endif
      ])
    ])
  ])
  AS_IF([test "x$$1" = "xyes"],[$2])
])
