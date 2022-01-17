## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

dnl check for --with-tdb option
AC_DEFUN([SQUID_CHECK_LIBTDB],[
AC_ARG_WITH(tdb,
  AS_HELP_STRING([--without-tdb],
                 [Do not use Samba TrivialDB. Default: auto-detect]), [
case "$with_tdb" in
  yes|no|auto)
    : # Nothing special to do here
    ;;
  *)
    AS_IF([test ! -d "$withval"],
      AC_MSG_ERROR([--with-tdb path ($with_tdb) does not point to a directory])
    )
    LIBTDB_PATH="-L$withval/lib"
    CPPFLAGS="-I$withval/include $CPPFLAGS"
  ;;
esac
])
AH_TEMPLATE(USE_TRIVIALDB,[Samba TrivialDB support is available])
AS_IF([test "x$with_tdb" != "xno"],[
  SQUID_STATE_SAVE(squid_libtdb_state)
  LIBS="$LIBS $LIBTDB_PATH"
  PKG_CHECK_MODULES([LIBTDB],[tdb],[CPPFLAGS="$CPPFLAGS $LIBTDB_CFLAGS"],[:])
  AC_CHECK_HEADERS([sys/stat.h tdb.h],,,[
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
  ])
  SQUID_STATE_ROLLBACK(squid_libtdb_state) #de-pollute LIBS

  AS_IF([test "x$with_tdb" = "xyes" -a "x$LIBTDB_LIBS" = "x"],
    AC_MSG_ERROR([Required TrivialDB library not found])
  )
  AS_IF([test "x$LIBTDB_LIBS" != "x"],[
    CXXFLAGS="$LIBTDB_CFLAGS $CXXFLAGS"
    LIBTDB_LIBS="$LIBTDB_PATH $LIBTDB_LIBS"
    AC_DEFINE_UNQUOTED(USE_TRIVIALDB, HAVE_TDB_H, [Samba TrivialDB support is available])
  ],[with_tdb=no])
])
AC_MSG_NOTICE([Samba TrivialDB library support: ${with_tdb:=auto} ${LIBTDB_PATH} ${LIBTDB_LIBS}])
AC_SUBST(LIBTDB_LIBS)
])
