/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _getaddrinfo_h
#define _getaddrinfo_h

/*
 *  Shamelessly duplicated from the fetchmail public sources
 *  for use by the Squid Project under GNU Public License.
 *
 * Update/Maintenance History:
 *
 *    15-Aug-2007 : Copied from fetchmail 6.3.8
 *          - added protection around library headers
 *
 *    16-Aug-2007 : Altered configure checks
 *                  Un-hacked slightly to use system gethostbyname()
 *
 *  Original License and code follows.
 */

/*
 *  This file is part of libESMTP, a library for submission of RFC 2822
 *  formatted electronic mail messages using the SMTP protocol described
 *  in RFC 2821.
 *
 *  Copyright (C) 2001,2002  Brian Stafford  <brian@stafford.uklinux.net>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Structure and prototypes taken from RFC 2553 */

/* These functions are provided by the OS */
#if !HAVE_DECL_GETADDRINFO

#ifndef EAI_SYSTEM
/* Not defined on mingw32. */
#define EAI_SYSTEM     11  /* System error returned in `errno'.  */
#endif
#ifndef EAI_OVERFLOW
/* Not defined on mingw32. */
#define EAI_OVERFLOW   12 /* Argument buffer overflow.  */
#endif

#ifndef IN_EXPERIMENTAL
#define IN_EXPERIMENTAL(a)  \
     ((((long int) (a)) & 0xf0000000) == 0xf0000000)
#endif

/* RFC 2553 / Posix resolver */
SQUIDCEXTERN int xgetaddrinfo (const char *nodename, const char *servname,
                               const struct addrinfo *hints, struct addrinfo **res);
#define getaddrinfo xgetaddrinfo

/* Free addrinfo structure and associated storage */
SQUIDCEXTERN void xfreeaddrinfo (struct addrinfo *ai);
#define freeaddrinfo    xfreeaddrinfo

/* Convert error return from getaddrinfo() to string */
SQUIDCEXTERN const char *xgai_strerror (int code);
#if !defined(gai_strerror)
#define gai_strerror    xgai_strerror
#endif

#endif /* HAVE_DECL_GETADDRINFO */
#endif /* _getaddrinfo_h */

