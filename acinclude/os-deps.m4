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


dnl check that strnstr() works fine. On Macos X it can cause a buffer overrun
dnl sets squid_cv_func_strnstr to "yes" or "no", and defines HAVE_STRNSTR
AC_DEFUN([SQUID_CHECK_FUNC_STRNSTR],[

# Yay!  This one is  a MacOSX brokenness.  Its not good enough
# to know that strnstr() exists, because MacOSX 10.4 have a bad
# copy that crashes with a buffer over-run!
AH_TEMPLATE(HAVE_STRNSTR,[MacOS brokenness: strnstr() can overrun on that system])
AC_CACHE_CHECK([if strnstr is well implemented], squid_cv_func_strnstr,
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
    // we expect this to succeed, or crash on over-run.
    // if it passes otherwise we may need a better check.
int main(int argc, char **argv)
{
    int size = 20;
    char *str = malloc(size);
    memset(str, 'x', size);
    strnstr(str, "fubar", size);
    return 0;
}
  ]])],[squid_cv_func_strnstr="yes"],[squid_cv_func_strnstr="no"],[])
)
if test "$squid_cv_func_strnstr" = "yes" ; then
  AC_DEFINE(HAVE_STRNSTR,1)
fi

]) dnl SQUID_CHECK_FUNC_STRNSTR

dnl check that va_copy is implemented and works
dnl sets squid_cv_func_va_copy and defines HAVE_VA_COPY
AC_DEFUN([SQUID_CHECK_FUNC_VACOPY],[

# check that the system provides a functional va_copy call

AH_TEMPLATE(HAVE_VA_COPY, [The system implements a functional va_copy() ])
AC_CACHE_CHECK(if va_copy is implemented, squid_cv_func_va_copy,
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdarg.h>
      #include <stdlib.h>
      int f (int i, ...) {
         va_list args1, args2;
         va_start (args1, i);
         va_copy (args2, args1);
         if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            return 1;
         va_end (args1); va_end (args2);
         return 0;
      }
      int main(int argc, char **argv) { return f (0, 42); }
      ]])],[squid_cv_func_va_copy="yes"],[squid_cv_func_va_copy="no"],[])
)
if test "$squid_cv_func_va_copy" = "yes" ; then
  AC_DEFINE(HAVE_VA_COPY, 1)
fi

]) dnl SQUID_CHECK_FUNC_VACOPY

dnl same sa SQUID_CHECK_FUNC_VACOPY, but checks __va_copy
dnl sets squid_cv_func___va_copy, and defines HAVE___VA_COPY
AC_DEFUN([SQUID_CHECK_FUNC___VACOPY],[

AH_TEMPLATE(HAVE___VA_COPY,[Some systems have __va_copy instead of va_copy])
AC_CACHE_CHECK(if __va_copy is implemented, squid_cv_func___va_copy,
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
      #include <stdarg.h>
      #include <stdlib.h>
      int f (int i, ...) {
         va_list args1, args2;
         va_start (args1, i);
         __va_copy (args2, args1);
         if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            return 1;
         va_end (args1); va_end (args2);
         return 0;
      }
      int main(int argc, char **argv) { return f (0, 42); }
      ]])],[squid_cv_func___va_copy="yes"],[squid_cv_func___va_copy="no"],[])
)
if test "$squid_cv_func___va_copy" = "yes" ; then
  AC_DEFINE(HAVE___VA_COPY, 1)
fi
]) dnl SQUID_CHECK_FUNC___VACOPY


dnl check that epoll actually works
dnl sets squid_cv_epoll_works to "yes" or "no"
AC_DEFUN([SQUID_CHECK_EPOLL],[

    AC_CACHE_CHECK(if epoll works, squid_cv_epoll_works,
      AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    int fd = epoll_create(256);
    if (fd < 0) {
	perror("epoll_create:");
	return 1;
    }
    return 0;
}
      ]])],[squid_cv_epoll_works=yes],[squid_cv_epoll_works=no],[]))

]) dnl SQUID_CHECK_EPOLL


dnl check that we have functional libcap2 headers
dnl sets squid_cv_sys_capability_works to "yes" or "no"

AC_DEFUN([SQUID_CHECK_FUNCTIONAL_LIBCAP2],[
  AC_CACHE_CHECK([for operational libcap2 headers], 
                 squid_cv_sys_capability_works,
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <stddef.h>
#include <sys/capability.h>
]], [[
    capget(NULL, NULL);
    capset(NULL, NULL);
]])],
   [squid_cv_sys_capability_works=yes],
   [squid_cv_sys_capability_works=no])
  )
])


dnl Ripped from Samba. Thanks!
dnl check that we have Unix sockets. Sets squid_cv_unixsocket to either yes or no depending on the check

AC_DEFUN([SQUID_CHECK_UNIX_SOCKET],[
  AC_CACHE_CHECK([for unix domain sockets],squid_cv_unixsocket, [
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>]], [[
  struct sockaddr_un sunaddr;
  sunaddr.sun_family = AF_UNIX;
  ]])],[squid_cv_unixsocket=yes],[squid_cv_unixsocket=no])])
])


dnl checks that the system provides struct mallinfo and mallinfo.mxfast.
dnl AC_DEFINEs HAVE_STRUCT_MALLINFO  and HAVE_STRUCT_MALLINFO_MXFAST if so

AC_DEFUN([SQUID_HAVE_STRUCT_MALLINFO],[
AC_CHECK_TYPE(struct mallinfo,AC_DEFINE(HAVE_STRUCT_MALLINFO,1,[The system provides struct mallinfo]),,[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif])
AC_CHECK_MEMBERS([struct mallinfo.mxfast],,,[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif])
])

dnl check the default FD_SETSIZE size.
dnl not cached, people are likely to tune this
dnl defines DEFAULT_FD_SETSIZE

AC_DEFUN([SQUID_CHECK_DEFAULT_FD_SETSIZE],[
AC_MSG_CHECKING(Default FD_SETSIZE value)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
int main(int argc, char **argv) {
	FILE *fp = fopen("conftestval", "w");
	fprintf (fp, "%d\n", FD_SETSIZE);
	return 0;
}
]])],[DEFAULT_FD_SETSIZE=`cat conftestval`],[DEFAULT_FD_SETSIZE=256],[DEFAULT_FD_SETSIZE=256])
AC_MSG_RESULT($DEFAULT_FD_SETSIZE)
AC_DEFINE_UNQUOTED(DEFAULT_FD_SETSIZE, $DEFAULT_FD_SETSIZE, [Default FD_SETSIZE value])
])


dnl checks the maximum number of filedescriptor we can open
dnl sets shell var squid_filedescriptors_num

AC_DEFUN([SQUID_CHECK_MAXFD],[
AC_MSG_CHECKING(Maximum number of filedescriptors we can open)
dnl damn! FreeBSD pthreads break dup2().
SQUID_STATE_SAVE(maxfd)
  case $host in
  i386-unknown-freebsd*)
      if echo "$LDFLAGS" | grep -q pthread; then
  	LDFLAGS=`echo $LDFLAGS | sed -e "s/-pthread//"`
      fi
  esac
  AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>	/* needed on FreeBSD */
#include <sys/param.h>
#include <sys/resource.h>
int main(int argc, char **argv) {
	FILE *fp;
	int i,j;
#if defined(__CYGWIN32__) || defined (__CYGWIN__)
    /* getrlimit and sysconf returns bogous values on cygwin32.
     * Number of fds is virtually unlimited in cygwin (sys/param.h)
     * __CYGWIN32__ is deprecated.
     */
    i = NOFILE;
#else
#if HAVE_SETRLIMIT
    struct rlimit rl;
#if defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
        perror("getrlimit: RLIMIT_NOFILE");
    } else {
#if defined(__APPLE__)
        /* asking for more than OPEN_MAX fails on Leopard */
        rl.rlim_cur = (OPEN_MAX < rl.rlim_max ? OPEN_MAX : rl.rlim_max);
#else
        rl.rlim_cur = rl.rlim_max;      /* set it to the max */
#endif
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
            perror("setrlimit: RLIMIT_NOFILE");
        }
    }
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, &rl) < 0) {
        perror("getrlimit: RLIMIT_OFILE");
    } else {
        rl.rlim_cur = rl.rlim_max;      /* set it to the max */
        if (setrlimit(RLIMIT_OFILE, &rl) < 0) {
            perror("setrlimit: RLIMIT_OFILE");
        }
    }
#endif /* RLIMIT_NOFILE */
#endif /* HAVE_SETRLIMIT */
	/* by starting at 2^14, we will never get higher
	than 2^15 for squid_filedescriptors_num */
        i = j = 1<<14;
        while (j) {
                j >>= 1;
                if (dup2(0, i) < 0) { 
                        i -= j;
                } else {
                        close(i);
                        i += j;
                }
        }
        i++;
#endif /* IF !DEF CYGWIN */
	fp = fopen("conftestval", "w");
	fprintf (fp, "%d\n", i & ~0x3F);
	return 0;
}
  ]])],[squid_filedescriptors_num=`cat conftestval`],[squid_filedescriptors_num=256],[squid_filedescriptors_num=256])
  dnl Microsoft MSVCRT.DLL supports 2048 maximum FDs
  case "$host_os" in
  mingw|mingw32)
    squid_filedescriptors_num="2048"
    ;;
  esac
  AC_MSG_RESULT($squid_filedescriptors_num)
SQUID_STATE_ROLLBACK(maxfd)

if test `expr $squid_filedescriptors_num % 64` != 0; then
    AC_MSG_WARN([$squid_filedescriptors_num is not an multiple of 64. This may cause issues on certain platforms.])
fi
])
