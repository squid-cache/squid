## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

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
  ]])],[squid_cv_func_strnstr="yes"],[squid_cv_func_strnstr="no"],[:])
)
if test "$squid_cv_func_strnstr" = "yes" ; then
  AC_DEFINE(HAVE_STRNSTR,1)
fi

]) dnl SQUID_CHECK_FUNC_STRNSTR

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
      ]])],[squid_cv_epoll_works=yes],[squid_cv_epoll_works=no],[:]))

]) dnl SQUID_CHECK_EPOLL

dnl check that /dev/poll actually works
dnl sets squid_cv_devpoll_works to "yes" or "no"
AC_DEFUN([SQUID_CHECK_DEVPOLL],[

    AC_CACHE_CHECK(if /dev/poll works, squid_cv_devpoll_works,
      AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/devpoll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    int fd = open("/dev/poll", O_RDWR);
    if (fd < 0) {
       perror("devpoll_create:");
       return 1;
    }
    return 0;
}
      ]])],[squid_cv_devpoll_works=yes],[squid_cv_devpoll_works=no],[:]))

]) dnl SQUID_CHECK_DEVPOLL


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


dnl From Samba. Thanks!
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
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
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
AC_CHECK_FUNCS(getrlimit setrlimit)
AC_MSG_CHECKING(Maximum number of filedescriptors we can open)
SQUID_STATE_SAVE(maxfd)
dnl FreeBSD pthreads break dup2().
  AS_CASE([$host_os],[freebsd],[ LDFLAGS=`echo $LDFLAGS | sed -e "s/-pthread//"` ])
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
#if HAVE_GETRLIMIT && HAVE_SETRLIMIT
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
  ]])],[squid_filedescriptors_limit=`cat conftestval`],[],[:])
  dnl Microsoft MSVCRT.DLL supports 2048 maximum FDs
  AS_CASE(["$host_os"],[mingw|mingw32],[squid_filedescriptors_limit="2048"])
  AC_MSG_RESULT($squid_filedescriptors_limit)
  AS_IF([ test "x$squid_filedescriptors_num" = "x" ],[
    AS_IF([ test "x$squid_filedescriptors_limit" != "x" ],[
      squid_filedescriptors_num=$squid_filedescriptors_limit
    ],[
      AC_MSG_NOTICE([Unable to detect filedescriptor limits. Assuming 256 is okay.])
      squid_filedescriptors_num=256
    ])
  ])
SQUID_STATE_ROLLBACK(maxfd)

AC_MSG_NOTICE([Default number of filedescriptors: $squid_filedescriptors_num])

AS_IF([ test `expr $squid_filedescriptors_num % 64` != 0 ],[
  AC_MSG_WARN([$squid_filedescriptors_num is not an multiple of 64. This may cause issues on certain platforms.])
])

AS_IF([ test "$squid_filedescriptors_num" -lt 512 ],[
  AC_MSG_WARN([$squid_filedescriptors_num may not be enough filedescriptors if your])
  AC_MSG_WARN([cache will be very busy.  Please see the FAQ page])
  AC_MSG_WARN([http://wiki.squid-cache.org/SquidFaq/TroubleShooting])
  AC_MSG_WARN([on how to increase your filedescriptor limit])
])
AC_DEFINE_UNQUOTED(SQUID_MAXFD,$squid_filedescriptors_num,[Maximum number of open filedescriptors])
])


dnl Check whether this OS defines sin6_len as a member of sockaddr_in6 as a backup to ss_len
dnl defines HAVE_SIN6_LEN_IN_SAI
dnl TODO: move to AC_CHECK_MEMBER?

AC_DEFUN([SQUID_CHECK_SIN6_LEN_IN_SAI],[
AC_CACHE_CHECK([for sin6_len field in struct sockaddr_in6],
                ac_cv_have_sin6_len_in_struct_sai, [
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
              ]], [[ struct sockaddr_in6 s; s.sin6_len = 1; ]])],[ ac_cv_have_sin6_len_in_struct_sai="yes" ],[ ac_cv_have_sin6_len_in_struct_sai="no" 
      ])
])
SQUID_DEFINE_BOOL(HAVE_SIN6_LEN_IN_SAI,$ac_cv_have_sin6_len_in_struct_sai,
      [Defined if struct sockaddr_in6 has sin6_len])
])


dnl Check whether this OS defines ss_len as a member of sockaddr_storage
dnl defines HAVE_SS_LEN_IN_SS
dnl TODO: move to AC_CHECK_MEMBER?

AC_DEFUN([SQUID_CHECK_SS_LEN_IN_SOCKADDR_STORAGE],[
AC_CACHE_CHECK([for ss_len field in struct sockaddr_storage],
		ac_cv_have_ss_len_in_struct_ss, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
		]], [[ struct sockaddr_storage s; s.ss_len = 1; ]])],[ ac_cv_have_ss_len_in_struct_ss="yes" ],[ ac_cv_have_ss_len_in_struct_ss="no" 
	])
])
SQUID_DEFINE_BOOL(HAVE_SS_LEN_IN_SS,$ac_cv_have_ss_len_in_struct_ss,
   [Define if sockaddr_storage has field ss_len])
])


dnl Check whether this OS defines sin_len as a member of sockaddr_in as a backup to ss_len
dnl defines HAVE_SIN_LEN_IN_SAI
dnl TODO: move to AC_CHECK_MEMBER?

AC_DEFUN([SQUID_CHECK_SIN_LEN_IN_SOCKADDR_IN],[
AC_CACHE_CHECK([for sin_len field in struct sockaddr_in],
                ac_cv_have_sin_len_in_struct_sai, [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
                ]], [[ struct sockaddr_in s; s.sin_len = 1; ]])],[ ac_cv_have_sin_len_in_struct_sai="yes" ],[ ac_cv_have_sin_len_in_struct_sai="no" 
        ])
])
SQUID_DEFINE_BOOL(HAVE_SIN_LEN_IN_SAI,$ac_cv_have_sin_len_in_struct_sai,[Define if sockaddr_in has field sin_len])
])


dnl detects default UDP buffer size
dnl not cached since people are likely to tune this
dnl defines SQUID_DETECT_UDP_SO_SNDBUF

AC_DEFUN([SQUID_DETECT_UDP_SND_BUFSIZE],[
AC_MSG_CHECKING(Default UDP send buffer size)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
int main(int argc, char **argv)
{
	FILE *fp;
        int fd,val=0;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        int len=sizeof(int);
	WSADATA wsaData;
	WSAStartup(2, &wsaData);
#else
        socklen_t len=sizeof(socklen_t);
#endif
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return 1;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&val, &len) < 0) return 1;
	WSACleanup();
#else
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &len) < 0) return 1;
#endif
	if (val<=0) return 1;
        fp = fopen("conftestval", "w");
        fprintf (fp, "%d\n", val);
	return 0;
}
]])],[SQUID_DETECT_UDP_SO_SNDBUF=`cat conftestval`],[SQUID_DETECT_UDP_SO_SNDBUF=16384],[SQUID_DETECT_UDP_SO_SNDBUF=16384])
AC_MSG_RESULT($SQUID_DETECT_UDP_SO_SNDBUF)
AC_DEFINE_UNQUOTED(SQUID_DETECT_UDP_SO_SNDBUF, $SQUID_DETECT_UDP_SO_SNDBUF,[UDP send buffer size])
])


dnl detects default UDP buffer size
dnl not cached since people are likely to tune this
dnl defines SQUID_DETECT_UDP_SO_RCVBUF

AC_DEFUN([SQUID_DETECT_UDP_RECV_BUFSIZE],[
AC_MSG_CHECKING(Default UDP receive buffer size)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
int main(int argc, char **argv)
{
	FILE *fp;
        int fd,val=0;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        int len=sizeof(int);
	WSADATA wsaData;
	WSAStartup(2, &wsaData);
#else
        socklen_t len=sizeof(socklen_t);
#endif
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return 1;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&val, &len) < 0) return 1;
	WSACleanup();
#else
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len) < 0) return 1;
#endif
	if (val <= 0) return 1;
	fp = fopen("conftestval", "w"); 
	fprintf (fp, "%d\n", val);
	return 0;
}
]])],[SQUID_DETECT_UDP_SO_RCVBUF=`cat conftestval`],[SQUID_DETECT_UDP_SO_RCVBUF=16384],[SQUID_DETECT_UDP_SO_RCVBUF=16384])
AC_MSG_RESULT($SQUID_DETECT_UDP_SO_RCVBUF)
AC_DEFINE_UNQUOTED(SQUID_DETECT_UDP_SO_RCVBUF, $SQUID_DETECT_UDP_SO_RCVBUF,[UDP receive buffer size])
])


dnl detects default TCP buffer size
dnl not cached since people are likely to tune this
dnl defines SQUID_TCP_SO_SNDBUF

AC_DEFUN([SQUID_DETECT_TCP_SND_BUFSIZE],[
AC_MSG_CHECKING(Default TCP send buffer size)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
int main(int argc, char **argv)
{
	FILE *fp;
        int fd,val=0;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        int len=sizeof(int);
	WSADATA wsaData;
	WSAStartup(2, &wsaData);
#else
        socklen_t len=sizeof(socklen_t);
#endif
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return 1;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&val, &len) < 0) return 1;
	WSACleanup();
#else
        if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &len) < 0) return 1;
#endif
	if (val <= 0) return 1;
	fp = fopen("conftestval", "w"); 
	fprintf (fp, "%d\n", val);
	return 0;
}
]])],[SQUID_TCP_SO_SNDBUF=`cat conftestval`],[SQUID_TCP_SO_SNDBUF=16384],[SQUID_TCP_SO_SNDBUF=16384])
AC_MSG_RESULT($SQUID_TCP_SO_SNDBUF)
if test $SQUID_TCP_SO_SNDBUF -gt 32768; then
    AC_MSG_NOTICE([Limiting send buffer size to 32K])
    SQUID_TCP_SO_SNDBUF=32768
fi
AC_DEFINE_UNQUOTED(SQUID_TCP_SO_SNDBUF, $SQUID_TCP_SO_SNDBUF,[TCP send buffer size])
])


dnl detects default TCP buffer size
dnl not cached since people are likely to tune this
dnl defines SQUID_TCP_SO_RECVBUF

AC_DEFUN([SQUID_DETECT_TCP_RECV_BUFSIZE],[
AC_MSG_CHECKING(Default TCP receive buffer size)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
int main(int argc, char **argv)
{
	FILE *fp;
        int fd,val=0;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        int len=sizeof(int);
	WSADATA wsaData;
	WSAStartup(2, &wsaData);
#else
        socklen_t len=sizeof(socklen_t);
#endif
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return 1;
#if (defined(WIN32) || defined(__WIN32__) || defined(__WIN32)) && !(defined(__CYGWIN32__) || defined(__CYGWIN__))
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&val, &len) < 0) return 1;
	WSACleanup();
#else
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &len) < 0) return 1;
#endif
	if (val <= 0) return 1;
	fp = fopen("conftestval", "w"); 
	fprintf (fp, "%d\n", val);
	return 0;
}
]])],[SQUID_TCP_SO_RCVBUF=`cat conftestval`],[SQUID_TCP_SO_RCVBUF=16384],[SQUID_TCP_SO_RCVBUF=16384])
AC_MSG_RESULT($SQUID_TCP_SO_RCVBUF)
if test $SQUID_TCP_SO_RCVBUF -gt 65535; then
    AC_MSG_NOTICE([Limiting receive buffer size to 64K])
    SQUID_TCP_SO_RCVBUF=65535
fi
AC_DEFINE_UNQUOTED(SQUID_TCP_SO_RCVBUF, $SQUID_TCP_SO_RCVBUF,[TCP receive buffer size])
])


dnl check if we need to define sys_errlist as external
dnl defines NEED_SYS_ERRLIST

AC_DEFUN([SQUID_CHECK_NEED_SYS_ERRLIST],[
AC_CACHE_CHECK(if sys_errlist is already defined, ac_cv_needs_sys_errlist,
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[char *s = sys_errlist;]])],[ac_cv_needs_sys_errlist="no"],[ac_cv_needs_sys_errlist="yes"])
)
SQUID_DEFINE_BOOL(NEED_SYS_ERRLIST,$ac_cv_needs_sys_errlist,[If we need to declare sys_errlist as extern])
])


dnl check if MAXPATHLEN is defined in the system headers
dnl or define it ourselves

AC_DEFUN([SQUID_CHECK_MAXPATHLEN],[
AC_MSG_CHECKING(for system-provided MAXPATHLEN)
AC_LINK_IFELSE([
  AC_LANG_PROGRAM([[
#include <sys/param.h>]], [[
int i = MAXPATHLEN;]])], [
  AC_MSG_RESULT(yes)], [
  AC_MSG_RESULT(no)
  AC_DEFINE(MAXPATHLEN,256,[If MAXPATHLEN has not been defined])])
])


dnl check that we have a working statvfs
dnl sets the ac_cv_func_statvfs shell variable and defines HAVE_STATVFS

AC_DEFUN([SQUID_CHECK_WORKING_STATVFS],[
AC_CACHE_CHECK(for working statvfs() interface,ac_cv_func_statvfs,[
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/statvfs.h>
]], [[
struct statvfs sfs;
sfs.f_blocks = sfs.f_bfree = sfs.f_frsize = 
sfs.f_files = sfs.f_ffree = 0;
statvfs("/tmp", &sfs);
]])],[ac_cv_func_statvfs=yes],[ac_cv_func_statvfs=no])
])
SQUID_DEFINE_BOOL(HAVE_STATVFS,$ac_cv_func_statvfs,[set to 1 if our system has statvfs(), and if it actually works])
])


dnl Check whether this OS defines f_frsize as a member of struct statfs
AC_DEFUN([SQUID_CHECK_F_FRSIZE_IN_STATFS],[
AC_CACHE_CHECK([for f_frsize field in struct statfs],
                ac_cv_have_f_frsize_in_struct_statfs, [
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_STATFS_H
#include <sts/statfs.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sts/statvfs.h>
#endif
#if HAVE_SYS_VFS_H
#include <sts/vfs.h>
#endif
                ]], [[ struct statfs s; s.f_frsize = 0; ]])],[ ac_cv_have_f_frsize_in_struct_statfs="yes" ],[ ac_cv_have_f_frsize_in_struct_statfs="no" 
        ])
])
SQUID_DEFINE_BOOL(HAVE_F_FRSIZE_IN_STATFS,$ac_cv_have_f_frsize_in_struct_statfs,[Define if struct statfs has field f_frsize (Linux 2.6 or later)])
])


dnl check that we can use the libresolv _dns_ttl_ hack
dnl sets the ac_cv_libresolv_dns_ttl_hack shell variable and defines LIBRESOLV_DNS_TTL_HACK

AC_DEFUN([SQUID_CHECK_LIBRESOLV_DNS_TTL_HACK],[
  AC_CACHE_CHECK(for libresolv _dns_ttl_ hack, ac_cv_libresolv_dns_ttl_hack, [
   AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern int _dns_ttl_;]], [[return _dns_ttl_;]])],
     [ac_cv_libresolv_dns_ttl_hack=yes],[ac_cv_libresolv_dns_ttl_hack=no]) ])
  SQUID_DEFINE_BOOL(LIBRESOLV_DNS_TTL_HACK,$ac_cv_libresolv_dns_ttl_hack,
     [libresolv.a has been hacked to export _dns_ttl_])
])


dnl checks for availability of some resolver fields
dnl sets ac_cv_have_res_ext_nsaddr_list shell variable
dnl defines _SQUID_RES_NSADDR6_COUNT _SQUID_RES_NSADDR6_LARRAY
dnl defines _SQUID_RES_NSADDR6_LPTR _SQUID_RES_NSADDR6_COUNT
dnl defines _SQUID_RES_NSADDR_LIST _SQUID_RES_NSADDR_COUNT

AC_DEFUN([SQUID_CHECK_RESOLVER_FIELDS],[
  AC_CACHE_CHECK(for _res_ext.nsaddr_list, ac_cv_have_res_ext_nsaddr_list,
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif
    ]], 
    [[_res_ext.nsaddr_list[[0]].s_addr;]])],[
      ac_cv_have_res_ext_nsaddr_list="yes" ],[
      ac_cv_have_res_ext_nsaddr_list="no"]))
  if test "$ac_cv_have_res_ext_nsaddr_list" = "yes" ; then
    AC_DEFINE(_SQUID_RES_NSADDR6_LARRAY,_res_ext.nsaddr_list,[If _res_ext structure has nsaddr_list member])
    AC_DEFINE(_SQUID_RES_NSADDR6_COUNT,ns6count,[Nameserver Counter for IPv6 _res_ext])
  fi

if test "$_SQUID_RES_NSADDR6_LIST" = ""; then
  AC_CACHE_CHECK(for _res._u._ext.nsaddrs, ac_cv_have_res_ext_nsaddrs,
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif
    ]], i
    [[_res._u._ext.nsaddrs[[0]]->sin6_addr;]])],
    [ac_cv_have_res_ext_nsaddrs="yes"],[ac_cv_have_res_ext_nsaddrs="no"]))
  if test "$ac_cv_have_res_ext_nsaddrs" = "yes" ; then
    AC_DEFINE(_SQUID_RES_NSADDR6_LPTR,_res._u._ext.nsaddrs,[If _res structure has _ext.nsaddrs member])
    AC_DEFINE(_SQUID_RES_NSADDR6_COUNT,_res._u._ext.nscount6,[Nameserver Counter for IPv6 _res])
  fi
fi

AC_CACHE_CHECK(for _res.nsaddr_list, ac_cv_have_res_nsaddr_list,
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif
  ]], [[_res.nsaddr_list[[0]];]])],
  [ac_cv_have_res_nsaddr_list="yes"],[ac_cv_have_res_nsaddr_list="no"]))
  if test $ac_cv_have_res_nsaddr_list = "yes" ; then
    AC_DEFINE(_SQUID_RES_NSADDR_LIST,_res.nsaddr_list,[If _res structure has nsaddr_list member])
    AC_DEFINE(_SQUID_RES_NSADDR_COUNT,_res.nscount,[Nameserver counter for IPv4 _res])
  fi

  if test "$_SQUID_RES_NSADDR_LIST" = ""; then
    AC_CACHE_CHECK(for _res.ns_list, ac_cv_have_res_ns_list,
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif
  ]], 
  [[_res.ns_list[[0]].addr;]])],
  [ac_cv_have_res_ns_list="yes"],[ac_cv_have_res_ns_list="no"]))
  if test $ac_cv_have_res_ns_list = "yes" ; then
    AC_DEFINE(_SQUID_RES_NSADDR_LIST,_res.ns_list,[If _res structure has ns_list member])
    AC_DEFINE(_SQUID_RES_NSADDR_COUNT,_res.nscount,[Nameserver counter for IPv4 _res])
  fi
fi
])


dnl checks the winsock library to use (ws2_32 or wsock32)
dnl may set ac_cv_func_select as a side effect
AC_DEFUN([SQUID_CHECK_WINSOCK_LIB],[
  AC_CHECK_HEADERS(winsock2.h winsock.h)
  SQUID_STATE_SAVE(winsock)
  SQUID_SEARCH_LIBS([squid_getprotobynumber],[ws2_32 wsock32],,,,[
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
/* ugly hack. */
void squid_getprotobynumber(void) {
    getprotobynumber(1);
}
  ])
  AC_MSG_CHECKING([for winsock library])
  case "$ac_cv_search_squid_getprotobynumber" in
    "no")
      AC_MSG_RESULT([winsock library not found])
      ;;
    "none required")
      AC_MSG_RESULT([winsock library already in LIBS])
      ;;
    "-lws2_32")
      AC_MSG_RESULT([winsock2])
      XTRA_LIBS="-lws2_32 $XTRA_LIBS"
      ac_cv_func_select='yes'
      ;;
    "-lwsock32")
      AC_MSG_RESULT([winsock])
      XTRA_LIBS="-lwsock32 $XTRA_LIBS"
      ac_cv_func_select='yes'
      ;;
  esac
  SQUID_STATE_ROLLBACK(winsock)
])

dnl check that setresuid is properly implemented.
dnl sets squid_cv_resuid_works to "yes" or "no"
AC_DEFUN([SQUID_CHECK_SETRESUID_WORKS],[
  AC_CACHE_CHECK(if setresuid is actually implemented, squid_cv_resuid_works,
    AC_RUN_IFELSE([
      AC_LANG_SOURCE([[
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
  int main(int argc, char **argv) {
    if(setresuid(-1,-1,-1)) {
      perror("setresuid:");
      return 1;
    }
    return 0;
  }
  ]])],[
    squid_cv_resuid_works="yes" ],[
    squid_cv_resuid_works="no" ],[:])
  )
])

dnl check that we have functional CPU clock access for the profiler
dnl sets squid_cv_profiler_works to "yes" or "no"

AC_DEFUN([SQUID_CHECK_FUNCTIONAL_CPU_PROFILER],[
  AC_CACHE_CHECK([for operational CPU clock access], 
                 squid_cv_cpu_profiler_works,
    AC_PREPROC_IFELSE([AC_LANG_SOURCE([[
#if defined(__GNUC__) && ( defined(__i386) || defined(__i386__) )
// okay
#elif defined(__GNUC__) && ( defined(__x86_64) || defined(__x86_64__) )
// okay
#elif defined(__GNUC__) && defined(__alpha)
// okay
#elif defined(_M_IX86) && defined(_MSC_VER) /* x86 platform on Microsoft C Compiler ONLY */
// okay
#else
#error This CPU is unsupported. No profiling available here.
#endif
  ]])],[
  squid_cv_cpu_profiler_works=yes],[
  squid_cv_cpu_profiler_works=no])
  )
])

dnl check whether recv takes a char* or void* as a second argument
AC_DEFUN([SQUID_CHECK_RECV_ARG_TYPE],[
  AC_CACHE_CHECK([whether recv takes a pointer to void or char as second argument],
         squid_cv_recv_second_arg_type, [
                 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
#endif
int main (int argc, char ** argv) {
       void *buf;
  recv(0,buf,0,0);
}
]])],[squid_cv_recv_second_arg_type=void],
     [squid_cv_recv_second_arg_type=char])
  AC_MSG_RESULT($squid_cv_recv_second_arg_type*)
  ])
  AC_DEFINE_UNQUOTED(RECV_ARG_TYPE,$squid_cv_recv_second_arg_type,
    [Base type of the second argument to recv(2)])
])


dnl check whether Solaris has broken IPFilter headers (Solaris 10 at least does)
AC_DEFUN([SQUID_CHECK_BROKEN_SOLARIS_IPFILTER],[
  if test "x$squid_cv_broken_ipfilter_minor_t" = "x"; then
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#     include <sys/types.h>
#     include <sys/time.h>
#     include <sys/ioccom.h>
#     include <netinet/in.h>

#     include <netinet/ip_compat.h>
#     include <netinet/ip_fil.h>
#     include <netinet/ip_nat.h>
    ]])],[
      AC_MSG_RESULT(no)
      squid_cv_broken_ipfilter_minor_t=0
    ],[
      ## on fail, test the hack
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#define minor_t fubaar
#       include <sys/types.h>
#       include <sys/time.h>
#       include <sys/ioccom.h>
#       include <netinet/in.h>
#undef minor_t
#       include <netinet/ip_compat.h>
#       include <netinet/ip_fil.h>
#       include <netinet/ip_nat.h>
      ]])],[
        AC_MSG_RESULT(yes)
        squid_cv_broken_ipfilter_minor_t=1
      ],[
        AC_MSG_ERROR(unable to make IPFilter work with netinet/ headers)
      ])
    ])
  fi

  AC_DEFINE_UNQUOTED(USE_SOLARIS_IPFILTER_MINOR_T_HACK,$squid_cv_broken_ipfilter_minor_t,
    [Workaround IPFilter minor_t breakage])

## check for IPFilter headers that require this hack
## (but first netinet/in.h and sys/ioccom.h which they depend on)
  AC_CHECK_HEADERS( \
	netinet/in.h \
	sys/ioccom.h \
	ip_compat.h \
	ip_fil_compat.h \
	ip_fil.h \
	ip_nat.h \
	netinet/ip_compat.h \
	netinet/ip_fil_compat.h \
	netinet/ip_fil.h \
	netinet/ip_nat.h \
  ,,,[
#if USE_SOLARIS_IPFILTER_MINOR_T_HACK
#define minor_t fubar
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#if USE_SOLARIS_IPFILTER_MINOR_T_HACK
#undef minor_t
#endif
#if HAVE_IP_COMPAT_H
#include <ip_compat.h>
#elif HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#if HAVE_IP_FIL_H
#include <ip_fil.h>
#elif HAVE_NETINET_IP_FIL_H
#include <netinet/ip_fil.h>
#endif
#if !defined(IPFILTER_VERSION)
#define IPFILTER_VERSION        5000004
#endif
  ])

## Solaris 10+ backported IPv6 NAT to their IPFilter v4.1 instead of using v5
  AC_CHECK_MEMBERS([
    struct natlookup.nl_inipaddr.in6,
    struct natlookup.nl_realipaddr.in6
  ],,,[
#if USE_SOLARIS_IPFILTER_MINOR_T_HACK
#define minor_t fubar
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#if USE_SOLARIS_IPFILTER_MINOR_T_HACK
#undef minor_t
#endif
#if HAVE_IP_COMPAT_H
#include <ip_compat.h>
#elif HAVE_NETINET_IP_COMPAT_H
#include <netinet/ip_compat.h>
#endif
#if HAVE_IP_FIL_H
#include <ip_fil.h>
#elif HAVE_NETINET_IP_FIL_H
#include <netinet/ip_fil.h>
#endif
#include <ip_nat.h>
  ])

])
