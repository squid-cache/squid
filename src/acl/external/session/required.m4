## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

SQUID_CHECK_LIBTDB
if test "$with_tdb" != "no"; then
    BUILD_HELPER="session"
fi

LIBBDB_LIBS=
AH_TEMPLATE(USE_BERKLEYDB,[BerkleyDB support is available])
if test "x$with_tdb" = "xno"; then
  AC_CHECK_HEADERS(db.h,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <db.h>]],[[
      DB_ENV *db_env = nullptr;
      db_env_create(&db_env, 0);
    ]])],[
      AC_DEFINE_UNQUOTED(USE_BERKLEYDB, HAVE_DB_H, [BerkleyDB support is available])
      BUILD_HELPER="session"
      LIBBDB_LIBS="-ldb"
    ],[])
  ])
fi
AC_SUBST(LIBBDB_LIBS)
