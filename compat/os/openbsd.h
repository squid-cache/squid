/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_OS_OPENBSD_H
#define SQUID_OS_OPENBSD_H

#if _SQUID_OPENBSD_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/*
 * Don't allow inclusion of malloc.h
 */
#if HAVE_MALLOC_H
#undef HAVE_MALLOC_H
#endif

/*
 *   This OS has at least one version that defines these as private
 *   kernel macros commented as being 'non-standard'.
 *   We need to use them, much nicer than the OS-provided __u*_*[]
 */
//#define s6_addr8  __u6_addr.__u6_addr8
//#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32

/* OpenBSD also hide v6only socket option we need for comm layer. :-( */
#if !defined(IPV6_V6ONLY)
#define IPV6_V6ONLY             27 // from OpenBSD 4.3 headers. (NP: does not match non-BSD OS values)
#endif

/* OpenBSD 4.8 and 4.9 require netinet/in.h before arpa/inet.h */
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#endif /* _SQUID_OPENBSD_ */
#endif /* SQUID_OS_OPENBSD_H */

