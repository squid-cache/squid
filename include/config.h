/*
 * $Id: config.h,v 1.5 2002/10/06 02:05:22 robertc Exp $
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

#elif defined(__CYGWIN32__)  || defined(__CYGWIN__)
#define _SQUID_CYGWIN_

#elif defined(WIN32) || defined(WINNT) || defined(__WIN32__) || defined(__WIN32)
#define _SQUID_MSWIN_

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

/* Typedefs for missing entries on a system */

#include "squid_types.h"

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

#if !defined(CACHEMGR_HOSTNAME)
#define CACHEMGR_HOSTNAME ""
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

#if __GNUC__
#define PRINTF_FORMAT_ARG1 __attribute__ ((format (printf, 1, 2)))
#define PRINTF_FORMAT_ARG2 __attribute__ ((format (printf, 2, 3)))
#define PRINTF_FORMAT_ARG3 __attribute__ ((format (printf, 3, 4)))
#else
#define PRINTF_FORMAT_ARG1
#define PRINTF_FORMAT_ARG2
#define PRINTF_FORMAT_ARG3
#endif

#endif /* SQUID_CONFIG_H */
