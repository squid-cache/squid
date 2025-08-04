/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Andrey Shorin <tolsty@tushino.com>
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 */

#ifndef SQUID_COMPAT_OS_MSWINDOWS_H
#define SQUID_COMPAT_OS_MSWINDOWS_H

#if _SQUID_WINDOWS_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

#include "compat/initgroups.h"

#if HAVE_DIRECT_H
#include <direct.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#if HAVE_STRING_H
#include <string.h>
#endif /* HAVE_FCNTL_H */
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#define ACL WindowsACL
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#if _MSC_VER == 1400
#define _CRT_SECURE_NO_DEPRECATE
#pragma warning( disable : 4290 )
#pragma warning( disable : 4996 )
#endif
#endif

#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
# define __USE_FILE_OFFSET64    1
#endif

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */

#if defined(__USE_FILE_OFFSET64)
typedef uint64_t ino_t;
#else
typedef unsigned long ino_t;
#endif

#define INT64_MAX _I64_MAX
#define INT64_MIN _I64_MIN

#include "default_config_file.h"
/* Some tricks for MS Compilers */
#define __STDC__ 1
#define THREADLOCAL __declspec(thread)

#elif defined(__GNUC__) /* gcc environment */

#define THREADLOCAL __attribute__((section(".tls")))

#endif /* _MSC_VER */

/* ONLY Microsoft C Compiler needs these: */
#if defined(_MSC_VER)
#define alloca _alloca
#define fileno _fileno
#define fstat _fstati64
#define lseek _lseeki64
#define memccpy _memccpy
#define mktemp _mktemp
#define snprintf _snprintf
#define stat _stati64
#define strcasecmp _stricmp
#define strlwr _strlwr
#define strncasecmp _strnicmp
#define tempnam _tempnam
#define vsnprintf _vsnprintf
#endif

/*  Microsoft C Compiler and CygWin need these. */
#if defined(_MSC_VER) || _SQUID_CYGWIN_
SQUIDCEXTERN int WIN32_ftruncate(int fd, off_t size);
#define ftruncate WIN32_ftruncate
SQUIDCEXTERN int WIN32_truncate(const char *pathname, off_t length);
#define truncate WIN32_truncate
#define chdir _chdir
#endif

/* All three compiler systems need these: */
#define dup _dup
#define dup2 _dup2
#define fdopen _fdopen
#define getcwd _getcwd
#define getpid _getpid
#define mkdir(p,F) mkdir((p))
#define pclose _pclose
#define popen _popen
#define putenv _putenv
#define setmode _setmode
#define sleep(t) Sleep((t)*1000)
#define umask _umask
#define unlink _unlink

#ifndef O_RDONLY
#define O_RDONLY        _O_RDONLY
#endif
#ifndef O_WRONLY
#define O_WRONLY        _O_WRONLY
#endif
#ifndef O_RDWR
#define O_RDWR          _O_RDWR
#endif
#ifndef O_APPEND
#define O_APPEND        _O_APPEND
#endif
#ifndef O_CREAT
#define O_CREAT         _O_CREAT
#endif
#ifndef O_TRUNC
#define O_TRUNC         _O_TRUNC
#endif
#ifndef O_EXCL
#define O_EXCL          _O_EXCL
#endif
#ifndef O_TEXT
#define O_TEXT          _O_TEXT
#endif
#ifndef O_BINARY
#define O_BINARY        _O_BINARY
#endif
#ifndef O_RAW
#define O_RAW           _O_BINARY
#endif
#ifndef O_TEMPORARY
#define O_TEMPORARY     _O_TEMPORARY
#endif
#ifndef O_NOINHERIT
#define O_NOINHERIT     _O_NOINHERIT
#endif
#ifndef O_SEQUENTIAL
#define O_SEQUENTIAL    _O_SEQUENTIAL
#endif
#ifndef O_RANDOM
#define O_RANDOM        _O_RANDOM
#endif
#ifndef O_NDELAY
#define O_NDELAY    0
#endif

#ifndef S_IFMT
#define S_IFMT   _S_IFMT
#endif
#ifndef S_IFDIR
#define S_IFDIR  _S_IFDIR
#endif
#ifndef S_IFCHR
#define S_IFCHR  _S_IFCHR
#endif
#ifndef S_IFREG
#define S_IFREG  _S_IFREG
#endif
#ifndef S_IREAD
#define S_IREAD  _S_IREAD
#endif
#ifndef S_IWRITE
#define S_IWRITE _S_IWRITE
#endif
#ifndef S_IEXEC
#define S_IEXEC  _S_IEXEC
#endif
#ifndef S_IRWXO
#define S_IRWXO 007
#endif

/* There are no group protection bits like these in Windows.
 * The values are used by umask() to remove permissions so
 * mapping to user permission bits will break file accesses.
 * Map group permissions to harmless zero instead.
 */
#ifndef S_IXGRP
#define S_IXGRP 0
#endif
#ifndef S_IWGRP
#define S_IWGRP 0
#endif
#ifndef S_IWOTH
#define S_IWOTH 0
#endif
#ifndef S_IXOTH
#define S_IXOTH 0
#endif

#if defined(_MSC_VER)
#define S_ISDIR(m) (((m) & _S_IFDIR) == _S_IFDIR)
#endif

#define SIGHUP  1   /* hangup */
#define SIGKILL 9   /* kill (cannot be caught or ignored) */
#define SIGBUS  10  /* bus error */
#define SIGPIPE 13  /* write on a pipe with no one to read it */
#define SIGCHLD 20  /* to parent on child stop or exit */
#define SIGUSR1 30  /* user defined signal 1 */
#define SIGUSR2 31  /* user defined signal 2 */

#if defined(_MSC_VER)
typedef int uid_t;
typedef int gid_t;
#endif

struct passwd {
    char    *pw_name;      /* user name */
    char    *pw_passwd;    /* user password */
    uid_t   pw_uid;        /* user id */
    gid_t   pw_gid;        /* group id */
    char    *pw_gecos;     /* real name */
    char    *pw_dir;       /* home directory */
    char    *pw_shell;     /* shell program */
};

struct group {
    char    *gr_name;      /* group name */
    char    *gr_passwd;    /* group password */
    gid_t   gr_gid;        /* group id */
    char    **gr_mem;      /* group members */
};

#if !HAVE_GETTIMEOFDAY
struct timezone {
    int tz_minuteswest; /* minutes west of Greenwich */
    int tz_dsttime; /* type of dst correction */
};
#endif

#define CHANGE_FD_SETSIZE 1
#if CHANGE_FD_SETSIZE && SQUID_MAXFD > DEFAULT_FD_SETSIZE
#define FD_SETSIZE SQUID_MAXFD
#endif

#include <process.h>
#include <errno.h>
#if HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#if !_SQUID_CYGWIN_
#undef IN_ADDR
#include <ws2tcpip.h>
#endif

#if (EAI_NODATA == EAI_NONAME)
#undef EAI_NODATA
#define EAI_NODATA WSANO_DATA
#endif

#if defined(_MSC_VER)
/* Hack to suppress compiler warnings on FD_SET() & FD_CLR() */
#pragma warning (push)
#pragma warning (disable:4142)
#endif

/* prevent inclusion of wingdi.h */
#define NOGDI
#include <ws2spi.h>

#if defined(_MSC_VER)
#pragma warning (pop)
#endif

#include <io.h>

#ifndef EISCONN
#define EISCONN WSAEISCONN
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef EALREADY
#define EALREADY WSAEALREADY
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif
#ifndef ERESTART
#define ERESTART WSATRY_AGAIN
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif
#ifndef ENETUNREACH
#define ENETUNREACH WSAENETUNREACH
#endif
#ifndef ENOTSUP
#define ENOTSUP WSAEOPNOTSUPP
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif

#undef h_errno
#define h_errno errno /* we'll set it ourselves */

#undef FD_CLR
#define FD_CLR(fd, set) do { \
    u_int __i; \
    SOCKET __sock = _get_osfhandle(fd); \
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count ; __i++) { \
        if (((fd_set FAR *)(set))->fd_array[__i] == __sock) { \
            while (__i < ((fd_set FAR *)(set))->fd_count-1) { \
                ((fd_set FAR *)(set))->fd_array[__i] = \
                    ((fd_set FAR *)(set))->fd_array[__i+1]; \
                __i++; \
            } \
            ((fd_set FAR *)(set))->fd_count--; \
            break; \
        } \
    } \
} while(0)

#undef FD_SET
#define FD_SET(fd, set) do { \
    u_int __i; \
    SOCKET __sock = _get_osfhandle(fd); \
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count; __i++) { \
        if (((fd_set FAR *)(set))->fd_array[__i] == (__sock)) { \
            break; \
        } \
    } \
    if (__i == ((fd_set FAR *)(set))->fd_count) { \
        if (((fd_set FAR *)(set))->fd_count < FD_SETSIZE) { \
            ((fd_set FAR *)(set))->fd_array[__i] = (__sock); \
            ((fd_set FAR *)(set))->fd_count++; \
        } \
    } \
} while(0)

#undef FD_ISSET
#define FD_ISSET(fd, set) Win32__WSAFDIsSet(fd, (fd_set FAR *)(set))

/* internal to Microsoft CRTLIB */
typedef struct {
    long osfhnd;    /* underlying OS file HANDLE */
    char osfile;    /* attributes of file (e.g., open in text mode?) */
    char pipech;    /* one char buffer for handles opened on pipes */
#ifdef _MT
    int lockinitflag;
    CRITICAL_SECTION lock;
#endif  /* _MT */
}   ioinfo;
#define IOINFO_L2E          5
#define IOINFO_ARRAY_ELTS   (1 << IOINFO_L2E)
#define _pioinfo(i) ( __pioinfo[(i) >> IOINFO_L2E] + ((i) & (IOINFO_ARRAY_ELTS - 1)) )
#define _osfile(i)  ( _pioinfo(i)->osfile )
#define _osfhnd(i)  ( _pioinfo(i)->osfhnd )
#if !defined(FOPEN)
#define FOPEN           0x01    /* file handle open */
#endif

#if defined(_MSC_VER)
SQUIDCEXTERN _CRTIMP ioinfo * __pioinfo[];
SQUIDCEXTERN int __cdecl _free_osfhnd(int);
#endif

SQUIDCEXTERN THREADLOCAL int ws32_result;

#if defined(__cplusplus)

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */

#endif

// stdlib <functional> definitions are required before std API redefinitions.
#include <functional>

/** \cond AUTODOCS-IGNORE */
namespace Squid
{
/** \endcond */

/*
 * Each of these functions is defined in the Squid namespace so as not to
 * clash with the winsock2.h definitions.
 * It is then paired with a #define to cause these wrappers to be used by
 * the main code instead of those system definitions.
 *
 * We do this wrapper in order to:
 * - cast the parameter types in only one place, and
 * - record errors in POSIX errno variable, and
 * - map the FD value used by Squid to the socket handes used by Windows.
 */

inline int
ioctl(int s, int c, void * a)
{
    if ((::ioctlsocket(_get_osfhandle(s), c, (u_long FAR *)a)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define ioctl(s,c,a) Squid::ioctl(s,c,a)

inline int
ioctlsocket(int s, long c, u_long FAR * a)
{
    if ((::ioctlsocket(_get_osfhandle(s), c, a)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define ioctlsocket(s,c,a) Squid::ioctlsocket(s,c,a)

inline int
shutdown(int s, int h)
{
    if (::shutdown(_get_osfhandle(s),h) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define shutdown(s,h) Squid::shutdown(s,h)

#undef WSADuplicateSocket
inline int
WSADuplicateSocket(int s, DWORD n, LPWSAPROTOCOL_INFO l)
{
#ifdef UNICODE
    if (::WSADuplicateSocketW(_get_osfhandle(s), n, l) == SOCKET_ERROR) {
#else
    if (::WSADuplicateSocketA(_get_osfhandle(s), n, l) == SOCKET_ERROR) {
#endif
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define WSADuplicateSocket(s,n,l) Squid::WSADuplicateSocket(s,n,l)

#undef WSASocket
inline int
WSASocket(int a, int t, int p, LPWSAPROTOCOL_INFO i, GROUP g, DWORD f)
{
    SOCKET result;
#ifdef UNICODE
    if ((result = ::WSASocketW(a, t, p, i, g, f)) == INVALID_SOCKET) {
#else
    if ((result = ::WSASocketA(a, t, p, i, g, f)) == INVALID_SOCKET) {
#endif
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return _open_osfhandle(result, 0);
}
#define WSASocket(a,t,p,i,g,f) Squid::WSASocket(a,t,p,i,g,f)

} /* namespace Squid */

#else /* #ifdef __cplusplus */
#define write      _write /* Needed in util.c */
#define open       _open /* Needed in win32lib.c */
#endif /* #ifdef __cplusplus */

/* provide missing definitions from resoruce.h */
/* NP: sys/resource.h and sys/time.h are apparently order-dependant. */
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#else
#define RUSAGE_SELF 0       /* calling process */
#define RUSAGE_CHILDREN -1      /* terminated child processes */

struct rusage {
    struct timeval ru_utime;    /* user time used */
    struct timeval ru_stime;    /* system time used */
    long ru_maxrss;         /* integral max resident set size */
    long ru_ixrss;          /* integral shared text memory size */
    long ru_idrss;          /* integral unshared data size */
    long ru_isrss;          /* integral unshared stack size */
    long ru_minflt;         /* page reclaims */
    long ru_majflt;         /* page faults */
    long ru_nswap;          /* swaps */
    long ru_inblock;        /* block input operations */
    long ru_oublock;        /* block output operations */
    long ru_msgsnd;         /* messages sent */
    long ru_msgrcv;         /* messages received */
    long ru_nsignals;       /* signals received */
    long ru_nvcsw;          /* voluntary context switches */
    long ru_nivcsw;         /* involuntary context switches */
};
#endif /* HAVE_SYS_RESOURCE_H */

#undef ACL

SQUIDCEXTERN int chroot(const char *dirname);
SQUIDCEXTERN int kill(pid_t, int);
SQUIDCEXTERN struct passwd * getpwnam(char *unused);
SQUIDCEXTERN struct group * getgrnam(char *unused);

static inline uid_t
geteuid(void)
{
    return 100;
}
static inline int
seteuid (uid_t euid)
{
    return 0;
}
static inline uid_t
getuid(void)
{
    return 100;
}
static inline int
setuid (uid_t uid)
{
    return 0;
}
static inline gid_t
getegid(void)
{
    return 100;
}
static inline int
setegid (gid_t egid)
{
    return 0;
}
static inline int
getgid(void)
{
    return 100;
}
static inline int
setgid (gid_t gid)
{
    return 0;
}

#if !HAVE_GETPAGESIZE
/* And now we define a compatibility layer */
size_t getpagesize();
#define HAVE_GETPAGESIZE 2
#endif

SQUIDCEXTERN void WIN32_ExceptionHandlerInit(void);
SQUIDCEXTERN int Win32__WSAFDIsSet(int fd, fd_set* set);
SQUIDCEXTERN DWORD WIN32_IpAddrChangeMonitorInit();

/* XXX: the logic around this is a bit warped:
 *   we #define ACL unconditionally at the top of this file,
 *   then #undef ACL unconditionally hafway down,
 *   then here re-define ACL to the same value as at the top,
 *   then include windows.h and #undef ACL again.
 */
#ifndef ACL
#define ACL WindowsACL
#define _MSWIN_ACL_WAS_NOT_DEFINED 1
#endif
#include <windows.h>
#if _MSWIN_ACL_WAS_NOT_DEFINED
#undef ACL
#undef _MSWIN_ACL_WAS_NOT_DEFINED
#endif

#if !HAVE_SYSLOG
/* syslog compatibility layer derives from git */
#define LOG_PID     0x01
#define LOG_EMERG   0
#define LOG_ALERT   1
#define LOG_CRIT    2
#define LOG_ERR     3
#define LOG_WARNING 4
#define LOG_NOTICE  5
#define LOG_INFO    6
#define LOG_DEBUG   7
#define LOG_DAEMON  (3<<3)

void openlog(const char *ident, int logopt, int facility);
void syslog(int priority, const char *fmt, ...);
#endif

#endif /* _SQUID_WINDOWS_ */
#endif /* SQUID_COMPAT_OS_MSWINDOWS_H */

