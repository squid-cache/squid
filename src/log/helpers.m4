## Copyright (C) 1996-2021 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# This file is supposed to run all the tests required to identify which
# configured modules are able to be built in this environment

# FIXME: de-duplicate $enable_log_daemon_helpers list containing double entries.

#define list of modules to build
auto_logdaemon_modules=no
if test "x${enable_log_daemon_helpers:=yes}" = "xyes" ;then
  enable_log_daemon_helpers=""
  SQUID_LOOK_FOR_MODULES([$srcdir/src/log],[enable_log_daemon_helpers])
  auto_logdaemon_modules=yes
fi
if test "x$enable_log_daemon_helpers" = "xnone" ; then
  enable_log_daemon_helpers=""
fi

LOG_DAEMON_HELPERS=""
enable_log_daemon_helpers="`echo $enable_log_daemon_helpers| sed -e 's/,/ /g;s/  */ /g'`"
if test "x$enable_log_daemon_helpers" != "xno"; then
  for helper in $enable_log_daemon_helpers ; do
    dir="$srcdir/src/log/$helper"

    # modules converted to autoconf macros already
    # NP: we only need this list because m4_include() does not accept variables
    if test "x$helper" = "xDB" ; then
      m4_include([src/log/DB/required.m4])

    elif test "x$helper" = "xfile" ; then
      m4_include([src/log/file/required.m4])

    # modules not yet converted to autoconf macros (or third party drop-in's)
    elif test -f "$dir/config.test" && sh "$dir/config.test" "$squid_host_os"; then
      BUILD_HELPER="$helper"
    fi

    if test -d "$srcdir/src/log/$helper"; then
      if test "$BUILD_HELPER" != "$helper"; then
        if test "x$auto_logdaemon_modules" = "xyes"; then
          AC_MSG_NOTICE([Log daemon helper $helper ... found but cannot be built])
        else
          AC_MSG_ERROR([Log daemon helper $helper ... found but cannot be built])
        fi
      else
       LOG_DAEMON_HELPERS="$LOG_DAEMON_HELPERS $BUILD_HELPER"
      fi
    else
      AC_MSG_ERROR([Log daemon helper $helper ... not found])
    fi
  done
fi
AC_MSG_NOTICE([Log daemon helpers to be built: $LOG_DAEMON_HELPERS])
AC_SUBST(LOG_DAEMON_HELPERS)
