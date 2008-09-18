/*
 * $Id: config.h,v 1.25.2.1 2008/02/25 03:41:38 amosjeffries Exp $
 *
 * AUTHOR: Duane Wessels
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

#ifndef SQUID_CONFIG_H
#define SQUID_CONFIG_H

#include "autoconf.h"		/* For GNU autoconf variables */
#include "version.h"

/* To keep API definitions clear */
#ifdef __cplusplus
#define SQUIDCEXTERN extern "C"
#else
#define SQUIDCEXTERN extern
#endif

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

#ifdef USE_POSIX_REGEX
#ifndef USE_RE_SYNTAX
#define USE_RE_SYNTAX	REG_EXTENDED	/* default Syntax */
#endif
#endif

/* define the _SQUID_TYPE_ based on a guess of the OS */
#if defined(__sun__) || defined(__sun)	/* SUN */
#define _SQUID_SUN_
#if defined(__SVR4)		/* SOLARIS */
#define _SQUID_SOLARIS_
#else /* SUNOS */
#define _SQUID_SUNOS_
#endif

#elif defined(__hpux)		/* HP-UX - SysV-like? */
#define _SQUID_HPUX_
#define _SQUID_SYSV_

#elif defined(__osf__)		/* OSF/1 */
#define _SQUID_OSF_

#elif defined(__ultrix)		/* Ultrix */
#define _SQUID_ULTRIX_

#elif defined(_AIX)		/* AIX */
#define _SQUID_AIX_

#elif defined(__linux__)	/* Linux */
#define _SQUID_LINUX_
#if USE_ASYNC_IO
#define _SQUID_LINUX_THREADS_
#endif

#elif defined(__FreeBSD__)	/* FreeBSD */
#define _SQUID_FREEBSD_
#if USE_ASYNC_IO && defined(LINUXTHREADS)
#define _SQUID_LINUX_THREADS_
#endif

#elif defined(__sgi__)	|| defined(sgi) || defined(__sgi)	/* SGI */
#define _SQUID_SGI_
#if !defined(_SVR4_SOURCE)
#define _SVR4_SOURCE		/* for tempnam(3) */
#endif
#if USE_ASYNC_IO
#define _ABI_SOURCE
#endif /* USE_ASYNC_IO */

#elif defined(__NeXT__)
#define _SQUID_NEXT_

#elif defined(__bsdi__)
#define _SQUID_BSDI_		/* BSD/OS */

#elif defined(__NetBSD__)
#define _SQUID_NETBSD_

#elif defined(__OpenBSD__)
#define _SQUID_OPENBSD_

#elif defined(__DragonFly__)
#define _SQUID_DRAGONFLY_

#elif defined(__CYGWIN32__)  || defined(__CYGWIN__)
#define _SQUID_CYGWIN_
#define _SQUID_WIN32_

#elif defined(WIN32) || defined(WINNT) || defined(__WIN32__) || defined(__WIN32)
#define _SQUID_MSWIN_
#define _SQUID_WIN32_
#include "squid_mswin.h"

#elif defined(__APPLE__)
#define _SQUID_APPLE_

#elif defined(sony_news) && defined(__svr4)
#define _SQUID_NEWSOS6_

#elif defined(__EMX__) || defined(OS2) || defined(__OS2__)
#define _SQUID_OS2_
/*
 *  FIXME: the os2 port of bash seems to have problems checking
 *  the return codes of programs in if statements.  These options
 *  need to be overridden.
 */
#endif

/* FD_SETSIZE must be redefined before including sys/types.h */

/*
 * On some systems, FD_SETSIZE is set to something lower than the
 * actual number of files which can be opened.  IRIX is one case,
 * NetBSD is another.  So here we increase FD_SETSIZE to our
 * configure-discovered maximum *before* any system includes.
 */
#define CHANGE_FD_SETSIZE 1

/*
 * Cannot increase FD_SETSIZE on Linux, but we can increase __FD_SETSIZE
 * with glibc 2.2 (or later? remains to be seen). We do this by including
 * bits/types.h which defines __FD_SETSIZE first, then we redefine
 * __FD_SETSIZE. Ofcourse a user program may NEVER include bits/whatever.h
 * directly, so this is a dirty hack!
 */
#if defined(_SQUID_LINUX_)
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#include <features.h>
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 2)
#if SQUID_MAXFD > DEFAULT_FD_SETSIZE
#include <bits/types.h>
#undef __FD_SETSIZE
#define __FD_SETSIZE SQUID_MAXFD
#endif
#endif
#endif

/*
 * Cannot increase FD_SETSIZE on FreeBSD before 2.2.0, causes select(2)
 * to return EINVAL.
 * --Marian Durkovic <marian@svf.stuba.sk>
 * --Peter Wemm <peter@spinner.DIALix.COM>
 */
#if defined(_SQUID_FREEBSD_)
#include <osreldate.h>
#if __FreeBSD_version < 220000
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif
#endif

/*
 * Trying to redefine CHANGE_FD_SETSIZE causes a slew of warnings
 * on Mac OS X Server.
 */
#if defined(_SQUID_APPLE_)
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif

/* Increase FD_SETSIZE if SQUID_MAXFD is bigger */
#if CHANGE_FD_SETSIZE && SQUID_MAXFD > DEFAULT_FD_SETSIZE
#define FD_SETSIZE SQUID_MAXFD
#endif



/* 
 * This is hack to allow compiling IPv6-IPv4 version,
 * not disturbing branches others than squid3-ipv6 
 */
#define IN_ADDR in_addr

/* Typedefs for missing entries on a system */

#include "squid_types.h"

/* int8_t */
#ifndef HAVE_INT8_T
#if HAVE_CHAR && SIZEOF_CHAR == 1
typedef char int8_t;
#else
#error NO 8 bit signed type available
#endif
#endif

/* u_int8_t */
#ifndef HAVE_U_INT8_T
#if HAVE_UINT8_T
typedef uint8_t u_int8_t;
#else
typedef unsigned char u_int8_t;
#endif
#endif

/* int16_t */
#ifndef HAVE_INT16_T
#if HAVE_SHORT && SIZEOF_SHORT == 2
typedef short int16_t;
#elif HAVE_INT && SIZEOF_INT == 2
typedef int int16_t;
#else
#error NO 16 bit signed type available
#endif
#endif

/* u_int16_t */
#ifndef HAVE_U_INT16_T
#if HAVE_UINT16_T
typedef uint16_t u_int16_t;
#else
typedef unsigned int16_t u_int16_t;
#endif
#endif

/* int32_t */
#ifndef HAVE_INT32_T
#if HAVE_INT && SIZEOF_INT == 4
typedef int int32_t;
#elif HAVE_LONG && SIZEOF_LONG == 4
typedef long int32_t;
#else
#error NO 32 bit signed type available
#endif
#endif

/* u_int32_t */
#ifndef HAVE_U_INT32_T
#if HAVE_UINT32_T
typedef uint32_t u_int32_t;
#else
typedef unsigned int32_t u_int32_t;
#endif
#endif

/* int64_t */
#ifndef HAVE_INT64_T
#if HAVE___INT64
typedef __int64 int64_t;
#elif HAVE_LONG && SIZEOF_LONG == 8
typedef long int64_t;
#elif HAVE_LONG_LONG && SIZEOF_LONG_LONG == 8
typedef long long int64_t;
#else
#error NO 64 bit signed type available
#endif
#endif

/* u_int64_t */
#ifndef HAVE_U_INT64_T
#if HAVE_UINT64_T
typedef uint64_t u_int64_t;
#else
typedef unsigned int64_t u_int64_t;
#endif
#endif


#ifndef HAVE_PID_T
typedef int pid_t;
#endif

#ifndef HAVE_SIZE_T
typedef unsigned int size_t;
#endif

#ifndef HAVE_SSIZE_T
typedef int ssize_t;
#endif

#ifndef HAVE_OFF_T
typedef int off_t;
#endif

#ifndef HAVE_MODE_T
typedef unsigned short mode_t;
#endif

#ifndef HAVE_FD_MASK
typedef unsigned long fd_mask;
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifndef HAVE_MTYP_T
typedef long mtyp_t;
#endif

/*
 * On Solaris 9 x86, gcc may includes a "fixed" set of old system include files
 * that is incompatible with the updated Solaris header files.
 */
#if defined(_SQUID_SOLARIS_) && (defined(i386) || defined(__i386))
#ifndef HAVE_PAD128_T
typedef union {
	long double	_q;
	int32_t		_l[4];
} pad128_t;
#endif
#ifndef HAVE_UPAD128_T
typedef union {
	long double	_q;
	uint32_t	_l[4];
} upad128_t;
#endif
#endif

/* 
 * Don't allow inclusion of malloc.h on FreeBSD, Next and OpenBSD 
 */
#if defined(HAVE_MALLOC_H) && (defined(_SQUID_FREEBSD_) || defined(_SQUID_NEXT_) || defined(_SQUID_OPENBSD_) || defined(_SQUID_DRAGONFLY_))
#undef HAVE_MALLOC_H
#endif

/*
 * res_init() is just a macro re-definition of __res_init on Linux (Debian/Ubuntu)
 */
#if !defined(HAVE_RES_INIT) && defined(HAVE___RES_INIT) && !defined(res_init)
#define res_init  __res_init
#define HAVE_RES_INIT  HAVE___RES_INIT
#endif

#if !defined(CACHEMGR_HOSTNAME)
#define CACHEMGR_HOSTNAME ""
#else
#define CACHEMGR_HOSTNAME_DEFINED 1
#endif

#if SQUID_DETECT_UDP_SO_SNDBUF > 16384
#define SQUID_UDP_SO_SNDBUF 16384
#else
#define SQUID_UDP_SO_SNDBUF SQUID_DETECT_UDP_SO_SNDBUF
#endif

#if SQUID_DETECT_UDP_SO_RCVBUF > 16384
#define SQUID_UDP_SO_RCVBUF 16384
#else
#define SQUID_UDP_SO_RCVBUF SQUID_DETECT_UDP_SO_RCVBUF
#endif

#ifdef HAVE_MEMCPY
#define xmemcpy(d,s,n) memcpy((d),(s),(n))
#elif HAVE_BCOPY
#define xmemcpy(d,s,n) bcopy((s),(d),(n))
#elif HAVE_MEMMOVE
#define xmemcpy(d,s,n) memmove((d),(s),(n))
#endif

#ifdef HAVE_MEMMOVE
#define xmemmove(d,s,n) memmove((d),(s),(n))
#elif HAVE_BCOPY
#define xmemmove(d,s,n) bcopy((s),(d),(n))
#endif

#define xisspace(x) isspace((unsigned char)x)
#define xtoupper(x) toupper((unsigned char)x)
#define xtolower(x) tolower((unsigned char)x)
#define xisdigit(x) isdigit((unsigned char)x)
#define xisascii(x) isascii((unsigned char)x)
#define xislower(x) islower((unsigned char)x)
#define xisalpha(x) isalpha((unsigned char)x)
#define xisprint(x) isprint((unsigned char)x)
#define xisalnum(x) isalnum((unsigned char)x)
#define xiscntrl(x) iscntrl((unsigned char)x)
#define xispunct(x) ispunct((unsigned char)x)
#define xisupper(x) isupper((unsigned char)x)
#define xisxdigit(x) isxdigit((unsigned char)x)
#define xisgraph(x) isgraph((unsigned char)x)

#if HAVE_RANDOM
#define squid_random random
#define squid_srandom srandom
#elif HAVE_LRAND48
#define squid_random lrand48
#define squid_srandom srand48
#else
#define squid_random rand
#define squid_srandom srand
#endif

/* gcc doesn't recognize the Windows native 64 bit formatting tags causing
 * the compile fail, so we must disable the check on native Windows.
 */  

#if __GNUC__ && !defined(_SQUID_MSWIN_)
#define PRINTF_FORMAT_ARG1 __attribute__ ((format (printf, 1, 2)))
#define PRINTF_FORMAT_ARG2 __attribute__ ((format (printf, 2, 3)))
#define PRINTF_FORMAT_ARG3 __attribute__ ((format (printf, 3, 4)))
#else
#define PRINTF_FORMAT_ARG1
#define PRINTF_FORMAT_ARG2
#define PRINTF_FORMAT_ARG3
#endif

/*
 * Determine if this is a leak check build or standard
 */
#if PURIFY
#define LEAK_CHECK_MODE 1
#elif WITH_VALGRIND
#define LEAK_CHECK_MODE 1
#elif XMALLOC_TRACE
#define LEAK_CHECK_MODE 1
#endif

/*
 * valgrind debug support
 */
#if WITH_VALGRIND
#include <valgrind/memcheck.h>
#undef VALGRIND_MAKE_NOACCESS
#undef VALGRIND_MAKE_WRITABLE
#undef VALGRIND_MAKE_READABLE
/* A little glue for older valgrind version prior to 3.2.0 */
#ifndef VALGRIND_MAKE_MEM_NOACCESS
#define VALGRIND_MAKE_MEM_NOACCESS VALGRIND_MAKE_NOACCESS
#define VALGRIND_MAKE_MEM_UNDEFINED VALGRIND_MAKE_WRITABLE
#define VALGRIND_MAKE_MEM_DEFINED VALGRIND_MAKE_READABLE
#define VALGRIND_CHECK_MEM_IS_ADDRESSABLE VALGRIND_CHECK_WRITABLE
#endif
#else
#define VALGRIND_MAKE_MEM_NOACCESS(a,b) (0)
#define VALGRIND_MAKE_MEM_UNDEFINED(a,b) (0)
#define VALGRIND_MAKE_MEM_DEFINED(a,b) (0)
#define VALGRIND_CHECK_MEM_IS_ADDRESSABLE(a,b) (0)
#define VALGRIND_CHECK_MEM_IS_DEFINED(a,b) (0)
#define VALGRIND_MALLOCLIKE_BLOCK(a,b,c,d)
#define VALGRIND_FREELIKE_BLOCK(a,b)
#define RUNNING_ON_VALGRIND 0
#endif /* WITH_VALGRIND */


/*
 * strnstr() is needed. The OS may not provide a working copy.
 */
#include "strnstr.h"

#endif /* SQUID_CONFIG_H */
