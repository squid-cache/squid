/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_OS_AIX_H
#define SQUID_OS_AIX_H

#if _SQUID_AIX_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/*
 * Syslog facility on AIX requires some portability wrappers
 */
#if HAVE_SYSLOG_H
#define _XOPEN_EXTENDED_SOURCE
#define _XOPEN_SOURCE_EXTENDED 1
#endif

/* AIX 6.1 does not define recvmsg() flag MSG_DONTWAIT */
#if !defined(MSG_DONTWAIT)
#define MSG_DONTWAIT 0
#endif

#endif /* _SQUID_AIX_ */
#endif /* SQUID_OS_AIX_H */

