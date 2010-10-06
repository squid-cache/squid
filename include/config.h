/*
 * $Id$
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

#if !defined(HAVE_SQUID)
/* sub-packages define their own version details */
#include "version.h"

#endif

/* default values for listen ports. Usually specified in squid.conf really */
#define CACHE_HTTP_PORT 3128
#define CACHE_ICP_PORT 3130

/* To keep API definitions clear */
#ifdef __cplusplus
#define SQUIDCEXTERN extern "C"
#else
#define SQUIDCEXTERN extern
#endif

#if _USE_INLINE_
#define _SQUID_INLINE_ inline
#else
#define _SQUID_INLINE_
#endif

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

#include "compat/compat.h"

#ifdef USE_POSIX_REGEX
#ifndef USE_RE_SYNTAX
#define USE_RE_SYNTAX	REG_EXTENDED	/* default Syntax */
#endif
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

#if HAVE_MEMCPY
#define xmemcpy(d,s,n) memcpy((d),(s),(n))
#elif HAVE_BCOPY
#define xmemcpy(d,s,n) bcopy((s),(d),(n))
#elif HAVE_MEMMOVE
#define xmemcpy(d,s,n) memmove((d),(s),(n))
#endif

#if HAVE_MEMMOVE
#define xmemmove(d,s,n) memmove((d),(s),(n))
#elif HAVE_BCOPY
#define xmemmove(d,s,n) bcopy((s),(d),(n))
#endif

#if HAVE_CTYPE_H
#include <ctype.h>
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

/* temp hack: needs to be pre-defined for now. */
#define SQUID_MAXPATHLEN 256

/*
 * strnstr() is needed. The OS may not provide a working copy.
 */
#include "strnstr.h"

/*
 * xstrtoul() and xstrtoui() are strtoul() and strtoui() with limits.
 */
#include "xstrto.h"

#endif /* SQUID_CONFIG_H */
