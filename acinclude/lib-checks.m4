dnl 
dnl AUTHOR: Squid Web Cache team
dnl
dnl SQUID Web Proxy Cache          http://www.squid-cache.org/
dnl ----------------------------------------------------------
dnl Squid is the result of efforts by numerous individuals from
dnl the Internet community; see the CONTRIBUTORS file for full
dnl details.   Many organizations have provided support for Squid's
dnl development; see the SPONSORS file for full details.  Squid is
dnl Copyrighted (C) 2001 by the Regents of the University of
dnl California; see the COPYRIGHT file for full details.  Squid
dnl incorporates software developed and/or copyrighted by other
dnl sources; see the CREDITS file for full details.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.


dnl checks whether dbopen needs -ldb to be added to libs
dnl sets ac_cv_dbopen_libdb to either "yes" or "no"

AC_DEFUN([SQUID_CHECK_DBOPEN_NEEDS_LIBDB],[
  AC_CACHE_CHECK(if dbopen needs -ldb,ac_cv_dbopen_libdb, [
    SQUID_STATE_SAVE(dbopen_libdb)
    LIBS="$LIBS -ldb"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_DB_185_H
#include <db_185.h>
#elif HAVE_DB_H
#include <db.h>
#endif]], 
[[dbopen("", 0, 0, DB_HASH, (void *)0L)]])],
    [ac_cv_dbopen_libdb="yes"],
    [ac_cv_dbopen_libdb="no"])
    SQUID_STATE_ROLLBACK(dbopen_libdb)
  ])
])


dnl check whether regex works by actually compiling one
dnl sets squid_cv_regex_works to either yes or no

AC_DEFUN([SQUID_CHECK_REGEX_WORKS],[
  AC_CACHE_CHECK([if the system-supplied regex lib actually works],squid_cv_regex_works,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_REGEX_H
#include <regex.h> 
#endif
]], [[
regex_t t; regcomp(&t,"",0);]])],
    [ squid_cv_regex_works=yes ],
    [ squid_cv_regex_works=no ])
  ])
])


AC_DEFUN([SQUID_CHECK_LIBIPHLPAPI],[
  AC_CACHE_CHECK([for libIpHlpApi],squid_cv_have_libiphlpapi,[
    SQUID_STATE_SAVE(iphlpapi)
    LIBS="$LIBS -liphlpapi"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
]], [[
  MIB_IPNETTABLE i;
  unsigned long isz=sizeof(i);
  GetIpNetTable(&i,&isz,FALSE);
    ]])],
    [squid_cv_have_libiphlpapi=yes
     SQUID_STATE_COMMIT(iphlpapi)],
    [squid_cv_have_libiphlpapi=no
     SQUID_STATE_ROLLBACK(iphlpapi)])
  ])
  SQUID_STATE_ROLLBACK(iphlpapi)
])
