## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_ARG_WITH(tdb,
  AS_HELP_STRING([--without-tdb],
                 [Do not use Samba TrivialDB. Default: auto-detect]), [
case "$with_tdb" in
  yes|no)
    : # Nothing special to do here
    ;;
  *)
    if test ! -d "$withval" ; then
      AC_MSG_ERROR([--with-tdb path does not point to a directory])
    fi
    LIBTDB_PATH="-L$withval/lib"
    CPPFLAGS="-I$withval/include $CPPFLAGS"
  esac
])
AH_TEMPLATE(USE_TRIVIALDB,[Samba TrivialDB support is available])
if test "x$with_tdb" != "xno"; then
  SQUID_STATE_SAVE(squid_libtdb_state)
  LIBS="$LIBS $LIBTDB_PATH"
  PKG_CHECK_MODULES([LIBTDB],[tdb],[CPPFLAGS="$CPPFLAGS $LIBTDB_CFLAGS"],[:])
  AC_CHECK_HEADERS([sys/stat.h tdb.h],,,[
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
  ])
  SQUID_STATE_ROLLBACK(squid_libtdb_state) #de-pollute LIBS

  if test "x$with_tdb" = "xyes" -a "x$LIBTDB_LIBS" = "x"; then
    AC_MSG_ERROR([Required TrivialDB library not found])
  fi
  if test "x$LIBTDB_LIBS" != "x" ; then
    CXXFLAGS="$LIBTDB_CFLAGS $CXXFLAGS"
    LIBTDB_LIBS="$LIBTDB_PATH $LIBTDB_LIBS"
    AC_DEFINE_UNQUOTED(USE_TRIVIALDB, HAVE_TDB_H, [Samba TrivialDB support is available])
    BUILD_HELPER="session"
  else
    with_tdb=no
  fi
fi
AC_MSG_NOTICE([Samba TrivialDB library support: ${with_tdb:=auto} ${LIBTDB_PATH} ${LIBTDB_LIBS}])
AC_SUBST(LIBTDB_LIBS)

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
