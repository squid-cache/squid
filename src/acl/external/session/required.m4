## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_CHECK_HEADERS(db.h,[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <db.h>]],[[
    DB_ENV *db_env = nullptr;
    db_env_create(&db_env, 0);
  ]])],[
    BUILD_HELPER="session"
  ],[])
])
