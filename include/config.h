/*
 * $Id: config.h,v 1.3 2001/10/22 23:55:43 hno Exp $
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
#ifndef socklen_t
#define socklen_t int
#endif
#ifndef fd_mask
#define fd_mask unsigned long
#endif
#endif

#if !defined(CACHEMGR_HOSTNAME)
#define CACHEMGR_HOSTNAME ""
#endif

#if SQUID_UDP_SO_SNDBUF > 16384
#undef SQUID_UDP_SO_SNDBUF
#define SQUID_UDP_SO_SNDBUF 16384
#endif

#if SQUID_UDP_SO_RCVBUF > 16384
#undef SQUID_UDP_SO_RCVBUF
#define SQUID_UDP_SO_RCVBUF 16384
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
#define PRINTF_FORMAT_ARG(pos) __attribute__ ((format (printf, pos, pos + 1)))
#else
#define PRINTF_FORMAT_ARG(pos)
#endif

#endif /* SQUID_CONFIG_H */
