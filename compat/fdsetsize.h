/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FDSETSIZE_H
#define SQUID_FDSETSIZE_H

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/* FD_SETSIZE must be redefined before including sys/types.h */
#if 0
/* AYJ: would dearly like to use this to enforce include order
    but at present some helpers don't follow the squid include methodology.
    that will need fixing later.
*/
#ifdef _SYS_TYPES_H
#error squid_fdsetsize.h for FDSETSIZE must be included before sys/types.h
#error Make sure that squid.h is the first file included by your .cc
#endif
#endif /* 0 */
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
#if _SQUID_LINUX_ || _SQUID_KFREEBSD_
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#include <features.h>
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 2)
#if SQUID_MAXFD > DEFAULT_FD_SETSIZE
#include <bits/types.h>
#if HAVE_LINUX_POSIX_TYPES_H
#include <linux/posix_types.h>
#endif
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
#if _SQUID_FREEBSD_
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
#if _SQUID_APPLE_
#undef CHANGE_FD_SETSIZE
#define CHANGE_FD_SETSIZE 0
#endif

/* Increase FD_SETSIZE if SQUID_MAXFD is bigger */
#if CHANGE_FD_SETSIZE && SQUID_MAXFD > DEFAULT_FD_SETSIZE
#define FD_SETSIZE SQUID_MAXFD
#endif

/*
 * Trap unintentional use of fd_set. Must not be used outside the
 * select code as it only supports FD_SETSIZE number of filedescriptors
 * and Squid may be running with a lot more..
 * But only for code linked into Squid, not the helpers.. (unlinkd, pinger)
 */
#ifdef SQUID_FDSET_NOUSE
# ifndef SQUID_HELPER
#  define fd_set ERROR_FD_SET_USED
# endif
#endif

#endif /* SQUID_FDSETSIZE_H */

