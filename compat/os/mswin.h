/*
 * AUTHOR: Andrey Shorin <tolsty@tushino.com>
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_OS_MSWIN_H
#define SQUID_OS_MSWIN_H

#if _SQUID_WINDOWS_

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
#if defined(__GNUC__)
#define NOMINMAX
#endif

#if defined _FILE_OFFSET_BITS && _FILE_OFFSET_BITS == 64
# define __USE_FILE_OFFSET64	1
#endif

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */

#if defined __USE_FILE_OFFSET64
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

#endif

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#define alloca _alloca
#endif
#define chdir _chdir
#define dup _dup
#define dup2 _dup2
#define fdopen _fdopen
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#define fileno _fileno
#define fstat _fstati64
#endif
#if !defined(_SQUID_MINGW_) // MinGW defines these properly
SQUIDCEXTERN int WIN32_ftruncate(int fd, off_t size);
#define ftruncate WIN32_ftruncate
SQUIDCEXTERN int WIN32_truncate(const char *pathname, off_t length);
#define truncate WIN32_truncate
#endif
#define getcwd _getcwd
#define getpid _getpid
#define getrusage WIN32_getrusage
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#define lseek _lseeki64
#define memccpy _memccpy
#define mkdir(p,F) _mkdir((p))
#define mktemp _mktemp
#endif
#define pclose _pclose
#define pipe WIN32_pipe
#define popen _popen
#define putenv _putenv
#define setmode _setmode
#define sleep(t) Sleep((t)*1000)
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#define snprintf _snprintf
#define stat _stati64
#define strcasecmp _stricmp
#define strdup _strdup
#define strlwr _strlwr
#define strncasecmp _strnicmp
#define tempnam _tempnam
#endif
#define umask _umask
#define unlink _unlink
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#define vsnprintf _vsnprintf
#endif

#define O_RDONLY        _O_RDONLY
#define O_WRONLY        _O_WRONLY
#define O_RDWR          _O_RDWR
#define O_APPEND        _O_APPEND

#define O_CREAT         _O_CREAT
#define O_TRUNC         _O_TRUNC
#define O_EXCL          _O_EXCL

#define O_TEXT          _O_TEXT
#define O_BINARY        _O_BINARY
#define O_RAW           _O_BINARY
#define O_TEMPORARY     _O_TEMPORARY
#define O_NOINHERIT     _O_NOINHERIT
#define O_SEQUENTIAL    _O_SEQUENTIAL
#define O_RANDOM        _O_RANDOM
#define O_NDELAY	0

#define S_IFMT   _S_IFMT
#define S_IFDIR  _S_IFDIR
#define S_IFCHR  _S_IFCHR
#define S_IFREG  _S_IFREG
#define S_IREAD  _S_IREAD
#define S_IWRITE _S_IWRITE
#define S_IEXEC  _S_IEXEC

#define S_IRWXO 007
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#define	S_ISDIR(m) (((m) & _S_IFDIR) == _S_IFDIR)
#endif

#define	SIGHUP	1	/* hangup */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	SIGBUS	10	/* bus error */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define SIGUSR1 30	/* user defined signal 1 */
#define SIGUSR2 31	/* user defined signal 2 */

#if !_SQUID_CYGWIN_
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

struct statfs {
    long    f_type;     /* type of filesystem (see below) */
    long    f_bsize;    /* optimal transfer block size */
    long    f_blocks;   /* total data blocks in file system */
    long    f_bfree;    /* free blocks in fs */
    long    f_bavail;   /* free blocks avail to non-superuser */
    long    f_files;    /* total file nodes in file system */
    long    f_ffree;    /* free file nodes in fs */
    long    f_fsid;     /* file system id */
    long    f_namelen;  /* maximum length of filenames */
    long    f_spare[6]; /* spare for later */
};

#if !HAVE_GETTIMEOFDAY
struct timezone {
    int	tz_minuteswest;	/* minutes west of Greenwich */
    int	tz_dsttime;	/* type of dst correction */
};
#endif

#define CHANGE_FD_SETSIZE 1
#if CHANGE_FD_SETSIZE && SQUID_MAXFD > DEFAULT_FD_SETSIZE
#define FD_SETSIZE SQUID_MAXFD
#endif

#include <process.h>
#include <errno.h>
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#include <winsock2.h>
#endif
#include <ws2tcpip.h>
#if (EAI_NODATA == EAI_NONAME)
#undef EAI_NODATA
#define EAI_NODATA WSANO_DATA
#endif
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
/* Hack to suppress compiler warnings on FD_SET() & FD_CLR() */
#pragma warning (push)
#pragma warning (disable:4142)
#endif
/* prevent inclusion of wingdi.h */
#define NOGDI
#include <ws2spi.h>
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
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
#define FOPEN           0x01    /* file handle open */

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */

SQUIDCEXTERN _CRTIMP ioinfo * __pioinfo[];
SQUIDCEXTERN int __cdecl _free_osfhnd(int);

#elif defined(__MINGW32__) /* MinGW environment */

__MINGW_IMPORT ioinfo * __pioinfo[];
SQUIDCEXTERN int _free_osfhnd(int);

#endif

SQUIDCEXTERN THREADLOCAL int ws32_result;

#define strerror(e) WIN32_strerror(e)
#define HAVE_STRERROR 1

#ifdef __cplusplus

inline
int close(int fd)
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

inline
int open(const char *filename, int oflag, int pmode = 0)
{
    return _open(filename, oflag, pmode & (_S_IREAD | _S_IWRITE));
}
#endif

inline
int read(int fd, void * buf, size_t siz)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    SOCKET sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0)
        return ::recv(sock, (char FAR *) buf, (int)siz, 0);
    else
        return _read(fd, buf, (unsigned int)siz);
}

inline
int write(int fd, const void * buf, size_t siz)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    SOCKET sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0)
        return ::send(sock, (char FAR *) buf, siz, 0);
    else
        return _write(fd, buf, siz);
}

inline
char *index(const char *s, int c)
{
    return (char *)strchr(s,c);
}

/** \cond AUTODOCS-IGNORE */
namespace Squid
{
/** \endcond */

inline
int accept(int s, struct sockaddr * a, size_t * l)
{
    SOCKET result;
    if ((result = ::accept(_get_osfhandle(s), a, (int *)l)) == INVALID_SOCKET) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return _open_osfhandle(result, 0);
}

inline
int bind(int s, struct sockaddr * n, int l)
{
    if (::bind(_get_osfhandle(s),n,l) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

inline
int connect(int s, const struct sockaddr * n, int l)
{
    if (::connect(_get_osfhandle(s),n,l) == SOCKET_ERROR) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return 0;
}

inline
struct hostent * gethostbyname (const char *n) {
    HOSTENT FAR * result;
    if ((result = ::gethostbyname(n)) == NULL)
        errno = WSAGetLastError();
    return result;
}
#define gethostbyname(n) Squid::gethostbyname(n)

inline
SERVENT FAR* getservbyname (const char * n, const char * p)
{
    SERVENT FAR * result;
    if ((result = ::getservbyname(n, p)) == NULL)
        errno = WSAGetLastError();
    return result;
}
#define getservbyname(n,p) Squid::getservbyname(n,p)

inline
HOSTENT FAR * gethostbyaddr(const char * a, int l, int t)
{
    HOSTENT FAR * result;
    if ((result = ::gethostbyaddr(a, l, t)) == NULL)
        errno = WSAGetLastError();
    return result;
}
#define gethostbyaddr(a,l,t) Squid::gethostbyaddr(a,l,t)

inline
int getsockname(int s, struct sockaddr * n, size_t * l)
{
    if ((::getsockname(_get_osfhandle(s), n, (int *)l)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

inline
int gethostname(char * n, size_t l)
{
    if ((::gethostname(n, l)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define gethostname(n,l) Squid::gethostname(n,l)

inline
int getsockopt(int s, int l, int o, void * v, int * n)
{
    Sleep(1);
    if ((::getsockopt(_get_osfhandle(s), l, o,(char *) v, n)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

/* Simple ioctl() emulation */
inline
int ioctl(int s, int c, void * a)
{
    if ((::ioctlsocket(_get_osfhandle(s), c, (u_long FAR *)a)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

inline
int ioctlsocket(int s, long c, u_long FAR * a)
{
    if ((::ioctlsocket(_get_osfhandle(s), c, a)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

inline
int listen(int s, int b)
{
    if (::listen(_get_osfhandle(s), b) == SOCKET_ERROR) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else
        return 0;
}
#define listen(s,b) Squid::listen(s,b)

inline
int recv(int s, void * b, size_t l, int f)
{
    int result;
    if ((result = ::recv(_get_osfhandle(s), (char *)b, l, f)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}

inline
int recvfrom(int s, void * b, size_t l, int f, struct sockaddr * fr, size_t * fl)
{
    int result;
    if ((result = ::recvfrom(_get_osfhandle(s), (char *)b, l, f, fr, (int *)fl)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}

inline
int select(int n, fd_set * r, fd_set * w, fd_set * e, struct timeval * t)
{
    int result;
    if ((result = ::select(n,r,w,e,t)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}
#define select(n,r,w,e,t) Squid::select(n,r,w,e,t)

inline
int send(int s, const void * b, size_t l, int f)
{
    int result;
    if ((result = ::send(_get_osfhandle(s), (char *)b, l, f)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}

inline
int sendto(int s, const void * b, size_t l, int f, const struct sockaddr * t, int tl)
{
    int result;
    if ((result = ::sendto(_get_osfhandle(s), (char *)b, l, f, t, tl)) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return result;
}

inline
int setsockopt(SOCKET s, int l, int o, const char * v, int n)
{
    SOCKET socket;

    socket = ((s == INVALID_SOCKET) ? s : (SOCKET)_get_osfhandle((int)s));

    if (::setsockopt(socket, l, o, v, n) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}
#define setsockopt(s,l,o,v,n) Squid::setsockopt(s,l,o,v,n)

inline
int shutdown(int s, int h)
{
    if (::shutdown(_get_osfhandle(s),h) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

inline
int socket(int f, int t, int p)
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

inline
int WSAAsyncSelect(int s, HWND h, unsigned int w, long e)
{
    if (::WSAAsyncSelect(_get_osfhandle(s), h, w, e) == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else
        return 0;
}

#undef WSADuplicateSocket
inline
int WSADuplicateSocket(int s, DWORD n, LPWSAPROTOCOL_INFO l)
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

#undef WSASocket
inline
int WSASocket(int a, int t, int p, LPWSAPROTOCOL_INFO i, GROUP g, DWORD f)
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

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#else
#define	RUSAGE_SELF	0		/* calling process */
#define	RUSAGE_CHILDREN	-1		/* terminated child processes */

struct rusage {
    struct timeval ru_utime;	/* user time used */
    struct timeval ru_stime;	/* system time used */
    long ru_maxrss;			/* integral max resident set size */
    long ru_ixrss;			/* integral shared text memory size */
    long ru_idrss;			/* integral unshared data size */
    long ru_isrss;			/* integral unshared stack size */
    long ru_minflt;			/* page reclaims */
    long ru_majflt;			/* page faults */
    long ru_nswap;			/* swaps */
    long ru_inblock;		/* block input operations */
    long ru_oublock;		/* block output operations */
    long ru_msgsnd;			/* messages sent */
    long ru_msgrcv;			/* messages received */
    long ru_nsignals;		/* signals received */
    long ru_nvcsw;			/* voluntary context switches */
    long ru_nivcsw;			/* involuntary context switches */
};
#endif /* HAVE_SYS_RESOURCE_H */

#undef ACL

#if !defined(getpagesize)
/* Windows may lack getpagesize() prototype */
SQUIDCEXTERN size_t getpagesize(void);
#endif

/* gcc doesn't recognize the Windows native 64 bit formatting tags causing
 * the compile fail, so we must disable the check on native Windows.
 */
#if __GNUC__
#define PRINTF_FORMAT_ARG1
#define PRINTF_FORMAT_ARG2
#define PRINTF_FORMAT_ARG3
#endif

#endif /* _SQUID_WINDOWS_ */
#endif /* SQUID_OS_MSWIN_H */
