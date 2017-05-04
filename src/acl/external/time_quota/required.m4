## Copyright (C) 1996-2017 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_CHECK_HEADERS(db_185.h,[BUILD_HELPER="time_quota"],[
  AC_CHECK_HEADERS(db.h,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <db.h>]],[[
      DB *db = dbopen("/tmp", O_CREAT | O_RDWR, 0666, DB_BTREE, NULL);
    ]])],[
      BUILD_HELPER="time_quota"
    ],[])
  ])
])
