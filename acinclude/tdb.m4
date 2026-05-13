dnl Copyright (C) 1996-2026 The Squid Software Foundation and contributors
dnl
dnl Squid software is distributed under GPLv2+ license and includes
dnl contributions from numerous individuals and organizations.
dnl Please see the COPYING and CONTRIBUTORS files for details.
dnl

dnl check for --with-tdb option
AC_DEFUN_ONCE([SQUID_CHECK_LIBTDB],[
SQUID_AUTO_LIB(tdb,[Samba TrivialDB])
SQUID_CHECK_LIB_WORKS(tdb,[
  SQUID_STATE_SAVE(squid_libtdb_state)
  LIBS="$LIBS $LIBTDB_PATH"
  PKG_CHECK_MODULES([LIBTDB],[tdb],[:],[:])
  CPPFLAGS="$CPPFLAGS $LIBTDB_CFLAGS"
  AC_CHECK_HEADERS([sys/stat.h tdb.h],,,[
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
  ])
  SQUID_STATE_ROLLBACK(squid_libtdb_state) #de-pollute LIBS
])
])
