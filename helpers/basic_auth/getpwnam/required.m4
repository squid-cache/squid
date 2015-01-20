## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

AC_CHECK_HEADERS([pwd.h],[
  # check for crypt(3), may require -lcrypt
  SQUID_STATE_SAVE(getpwnam_helper)
  LIBS="$LIBS $CRYPTLIB"
  AC_CHECK_FUNCS(crypt)
  SQUID_STATE_ROLLBACK(getpwnam_helper)

  # unconditionally requires crypt(3), for now
  if test "x$ac_cv_func_crypt" != "x"; then
    AC_CHECK_HEADERS(unistd.h crypt.h shadow.h)

    BUILD_HELPER="getpwnam"
  fi
])
