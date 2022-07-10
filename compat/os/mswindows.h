/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * AUTHOR: Andrey Shorin <tolsty@tushino.com>
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 */

#ifndef SQUID_OS_MSWINDOWS_H
#define SQUID_OS_MSWINDOWS_H

#if _SQUID_WINDOWS_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/* we target Windows XP and later - some API are missing otherwise */
#if _SQUID_MINGW_
#if WINVER < 0x0501
#undef WINVER
#define WINVER 0x0501
#undef _WIN32_WINNT
#define _WIN32_WINNT WINVER
#endif
#endif /* _SQUID_MINGW_ */

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

/* Some MinGW version defines min() and max() as macros
   causing the fail of the build process. The following
   #define will disable that definition
 */
#if defined(__GNUC__) && !NOMINMAX
#define NOMINMAX
#endif

/// some builds of MinGW do not define IPV6_V6ONLY socket option
#if !defined(IPV6_V6ONLY)
#define IPV6_V6ONLY 27
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

/*  Microsoft C Compiler and CygWin need these. MinGW does not */
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

#if _SQUID_MINGW_
typedef unsigned char boolean;
typedef unsigned char u_char;
typedef unsigned int u_int;
#endif

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
#elif HAVE_WINSOCK_H
#include <winsock.h>
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

typedef char * caddr_t;

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "NUL"
#endif

#undef FD_CLOSE
#undef FD_OPEN
#undef FD_READ
#undef FD_WRITE

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

#if _SQUID_MINGW_
__MINGW_IMPORT ioinfo * __pioinfo[];
SQUIDCEXTERN int _free_osfhnd(int);
#endif

SQUIDCEXTERN THREADLOCAL int ws32_result;

#if defined(__cplusplus)

inline int
close(int fd)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    SOCKET sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0) {
        int result = 0;
        if (closesocket(sock) == SOCKET_ERROR) {
            errno = WSAGetLastError();
            result = 1;
        }
        _free_osfhnd(fd);
        _osfile(fd) = 0;
        return result;
    } else
        return _close(fd);
}

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */

#ifndef _S_IREAD
#define _S_IREAD 0x0100
#endif

#ifndef _S_IWRITE
#define _S_IWRITE 0x0080
#endif

inline int
open(const char *filename, int oflag, int pmode = 0)
{
    return _open(filename, oflag, pmode & (_S_IREAD | _S_IWRITE));
}
#endif

inline int
read(int fd, void * buf, size_t siz)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    SOCKET sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0)
        return ::recv(sock, (char FAR *) buf, (int)siz, 0);
    else
        return _read(fd, buf, (unsigned int)siz);
}

inline int
write(int fd, const void * buf, size_t siz)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    SOCKET sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0)
        return ::send(sock, (char FAR *) buf, siz, 0);
    else
        return _write(fd, buf, siz);
}

// stdlib <functional> definitions are required before std API redefinitions.
#include <functional>

/** \cond AUTODOCS-IGNORE */
namespace Squid
{
/** \endcond */

/*
 * Each of these functions is defined in the Squid namespace so as not to
 * clash with the winsock.h and winsock2.h definitions.
 * It is then paired with a #define to cause these wrappers to be used by
 * the main code instead of those system definitions.
 *
 * We do this wrapper in order to:
 * - cast the parameter types in only one place, and
 * - record errors in POSIX errno variable, and
 * - map the FD value used by Squid to the socket handes used by Windows.
 */

inline int
accept(int s, struct sockaddr * a, socklen_t * l)
{
    SOCKET result;
    if ((result = ::accept(_get_osfhandle(s), a, l)) == INVALID_SOCKET) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return _open_osfhandle(result, 0);
}
#define accept(s,a,l) Squid::accept(s,a,reinterpret_cast<socklen_t*>(l))

inline int
bind(int s, const struct sockaddr * n, socklen_t l)
{
    if (::bind(_get_osfhandle(s),n,l) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define bind(s,n,l) Squid::bind(s,n,l)

inline int
connect(int s, const struct sockaddr * n, socklen_t l)
{
    if (::connect(_get_osfhandle(s),n,l) == SOCKET_ERROR) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return 0;
}
#define connect(s,n,l) Squid::connect(s,n,l)

inline struct hostent *
gethostbyname(const char *n) {
    HOSTENT FAR * result;
    if ((result = ::gethostbyname(n)) == NULL)
        errno = WSAGetLastError();
    return result;
}
#define gethostbyname(n) Squid::gethostbyname(n)

inline SERVENT FAR *
getservbyname(const char * n, const char * p)
{
    SERVENT FAR * result;
    if ((result = ::getservbyname(n, p)) == NULL)
        errno = WSAGetLastError();
    return result;
}
#define getservbyname(n,p) Squid::getservbyname(n,p)

inline HOSTENT FAR *
gethostbyaddr(const void * a, size_t l, int t)
{
    HOSTENT FAR * result;
    if ((result = ::gethostbyaddr((const char*)a, l, t)) == NULL)
        errno = WSAGetLastError();
    return result;
}
#define gethostbyaddr(a,l,t) Squid::gethostbyaddr(a,l,t)

inline int
getsockname(int s, struct sockaddr * n, socklen_t * l)
{
    int i=*l;
    if (::getsockname(_get_osfhandle(s), n, &i) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define getsockname(s,a,l) Squid::getsockname(s,a,reinterpret_cast<socklen_t*>(l))

inline int
gethostname(char * n, size_t l)
{
    if ((::gethostname(n, l)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define gethostname(n,l) Squid::gethostname(n,l)

inline int
getsockopt(int s, int l, int o, void * v, socklen_t * n)
{
    Sleep(1);
    if ((::getsockopt(_get_osfhandle(s), l, o,(char *) v, n)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define getsockopt(s,l,o,v,n) Squid::getsockopt(s,l,o,v,n)

#if HAVE_DECL_INETNTOPA || HAVE_DECL_INET_NTOP
inline char *
inet_ntop(int af, const void *src, char *dst, size_t size)
{
#if HAVE_DECL_INETNTOPA
    return (char*)InetNtopA(af, const_cast<void*>(src), dst, size);
#else // HAVE_DECL_INET_NTOP
    return ::inet_ntop(af, src, dst, size);
#endif
}
#define inet_ntop(a,s,d,l) Squid::inet_ntop(a,s,d,l)
#endif // let compat/inet_ntop.h deal with it

#if HAVE_DECL_INETPTONA || HAVE_DECL_INET_PTON
inline char *
inet_pton(int af, const void *src, char *dst)
{
#if HAVE_DECL_INETPTONA
    return (char*)InetPtonA(af, const_cast<void*>(src), dst);
#else // HAVE_DECL_INET_PTON
    return ::inet_pton(af, src, dst);
#endif
}
#define inet_pton(a,s,d) Squid::inet_pton(a,s,d)
#endif // let compat/inet_pton.h deal with it

/* Simple ioctl() emulation */
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
listen(int s, int b)
{
    if (::listen(_get_osfhandle(s), b) == SOCKET_ERROR) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return 0;
}
#define listen(s,b) Squid::listen(s,b)

inline ssize_t
recv(int s, void * b, size_t l, int f)
{
    ssize_t result;
    if ((result = ::recv(_get_osfhandle(s), (char *)b, l, f)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}
#define recv(s,b,l,f) Squid::recv(s,b,l,f)

inline ssize_t
recvfrom(int s, void * b, size_t l, int f, struct sockaddr * fr, socklen_t * fl)
{
    ssize_t result;
    int ifl=*fl;
    if ((result = ::recvfrom(_get_osfhandle(s), (char *)b, l, f, fr, &ifl)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}
#define recvfrom(s,b,l,f,r,n) Squid::recvfrom(s,b,l,f,r,reinterpret_cast<socklen_t*>(n))

inline int
select(int n, fd_set * r, fd_set * w, fd_set * e, struct timeval * t)
{
    int result;
    if ((result = ::select(n,r,w,e,t)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}
#define select(n,r,w,e,t) Squid::select(n,r,w,e,t)

inline ssize_t
send(int s, const char * b, size_t l, int f)
{
    ssize_t result;
    if ((result = ::send(_get_osfhandle(s), b, l, f)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}
#define send(s,b,l,f) Squid::send(s,reinterpret_cast<const char*>(b),l,f)

inline ssize_t
sendto(int s, const void * b, size_t l, int f, const struct sockaddr * t, socklen_t tl)
{
    ssize_t result;
    if ((result = ::sendto(_get_osfhandle(s), (char *)b, l, f, t, tl)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}
#define sendto(a,b,l,f,t,n) Squid::sendto(a,b,l,f,t,n)

inline int
setsockopt(SOCKET s, int l, int o, const void * v, socklen_t n)
{
    SOCKET socket;

    socket = ((s == INVALID_SOCKET) ? s : (SOCKET)_get_osfhandle((int)s));

    if (::setsockopt(socket, l, o, (const char *)v, n) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define setsockopt(s,l,o,v,n) Squid::setsockopt(s,l,o,v,n)

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

inline int
socket(int f, int t, int p)
{
    SOCKET result;
    if ((result = ::socket(f, t, p)) == INVALID_SOCKET) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return _open_osfhandle(result, 0);
}
#define socket(f,t,p) Squid::socket(f,t,p)

inline int
pipe(int pipefd[2])
{
    return _pipe(pipefd,4096,_O_BINARY);
}
#define pipe(a) Squid::pipe(a)

inline int
WSAAsyncSelect(int s, HWND h, unsigned int w, long e)
{
    if (::WSAAsyncSelect(_get_osfhandle(s), h, w, e) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define WSAAsyncSelect(s,h,w,e) Squid::WSAAsyncSelect(s,h,w,e)

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
#define connect(s,n,l) \
    (SOCKET_ERROR == connect(_get_osfhandle(s),n,l) ? \
    (WSAEMFILE == (errno = WSAGetLastError()) ? errno = EMFILE : -1, -1) : 0)
#define gethostbyname(n) \
    (NULL == ((HOSTENT FAR*)(ws32_result = (int)gethostbyname(n))) ? \
    (errno = WSAGetLastError()), (HOSTENT FAR*)NULL : (HOSTENT FAR*)ws32_result)
#define gethostname(n,l) \
    (SOCKET_ERROR == gethostname(n,l) ? \
    (errno = WSAGetLastError()), -1 : 0)
#define recv(s,b,l,f) \
    (SOCKET_ERROR == (ws32_result = recv(_get_osfhandle(s),b,l,f)) ? \
    (errno = WSAGetLastError()), -1 : ws32_result)
#define sendto(s,b,l,f,t,tl) \
    (SOCKET_ERROR == (ws32_result = sendto(_get_osfhandle(s),b,l,f,t,tl)) ? \
    (errno = WSAGetLastError()), -1 : ws32_result)
#define select(n,r,w,e,t) \
    (SOCKET_ERROR == (ws32_result = select(n,r,w,e,t)) ? \
    (errno = WSAGetLastError()), -1 : ws32_result)
#define socket(f,t,p) \
    (INVALID_SOCKET == ((SOCKET)(ws32_result = (int)socket(f,t,p))) ? \
    ((WSAEMFILE == (errno = WSAGetLastError()) ? errno = EMFILE : -1), -1) : \
    (SOCKET)_open_osfhandle(ws32_result,0))
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

/* for some reason autoconf misdetects getpagesize.. */
#if HAVE_GETPAGESIZE && _SQUID_MINGW_
#undef HAVE_GETPAGESIZE
#endif

#if !HAVE_GETPAGESIZE
/* And now we define a compatibility layer */
size_t getpagesize();
#define HAVE_GETPAGESIZE 2
#endif

SQUIDCEXTERN void WIN32_ExceptionHandlerInit(void);
SQUIDCEXTERN int Win32__WSAFDIsSet(int fd, fd_set* set);
SQUIDCEXTERN DWORD WIN32_IpAddrChangeMonitorInit();

/* gcc doesn't recognize the Windows native 64 bit formatting tags causing
 * the compile fail, so we must disable the check on native Windows.
 */
#if __GNUC__
#define PRINTF_FORMAT_ARG1
#define PRINTF_FORMAT_ARG2
#define PRINTF_FORMAT_ARG3
#endif

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

#if _SQUID_MINGW_
/* MinGW missing bits from sys/wait.h */
/* A status looks like:
 *  <2 bytes info> <2 bytes code>
 *
 *  <code> == 0, child has exited, info is the exit value
 *  <code> == 1..7e, child has exited, info is the signal number.
 *  <code> == 7f, child has stopped, info was the signal number.
 *  <code> == 80, there was a core dump.
 */
#define WIFEXITED(w)    (((w) & 0xff) == 0)
#define WIFSIGNALED(w)  (((w) & 0x7f) > 0 && (((w) & 0x7f) < 0x7f))
#define WIFSTOPPED(w)   (((w) & 0xff) == 0x7f)
#define WEXITSTATUS(w)  (((w) >> 8) & 0xff)
#define WTERMSIG(w) ((w) & 0x7f)
#define WSTOPSIG    WEXITSTATUS
#endif

/* prototypes */
void WIN32_maperror(unsigned long WIN32_oserrno);

#endif /* _SQUID_WINDOWS_ */
#endif /* SQUID_OS_MSWINDOWS_H */

