/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_OS_AIX_H
#define SQUID_COMPAT_OS_AIX_H

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

#endif /* _SQUID_AIX_ */
#endif /* SQUID_COMPAT_OS_AIX_H */

