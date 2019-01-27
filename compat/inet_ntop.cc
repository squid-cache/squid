/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 *  Shamelessly duplicated from the bind9 public sources
 *  for use by the Squid Project under ISC written permission
 *  included "as found" below.
 *
 * Update/Maintenance History:
 *
 *    24-Sep-2007 : Copied from bind 9.3.3
 *          - Added protection around libray headers
 *          - Altered configure checks
 *          - Un-hacked slightly to use system gethostbyname()
 *
 *    06-Oct-2007 : Various fixes to allow the build on MinGW
 *
 *    28-Oct-2007: drop some dead code. now tested working without.
 *
 *    04-Nov-2010: drop SPRINTF casting macro
 *
 *    13-Jan-2015 : Various fixed for C++ and MinGW native build
 *
 *  Original License and code follows.
 */

#include "squid.h"

#if !HAVE_DECL_INET_NTOP

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static const char rcsid[] = "inet_ntop.c,v 1.1.2.1.8.2 2005/11/03 23:08:40 marka Exp";
#endif /* LIBC_SCCS and not lint */

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif

#if ! defined(NS_INADDRSZ)
#define NS_INADDRSZ      4
#endif
#if ! defined(NS_IN6ADDRSZ)
#define NS_IN6ADDRSZ    16
#endif
#if ! defined(NS_INT16SZ)
#define NS_INT16SZ      2
#endif

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *inet_ntop4 (const u_char *src, char *dst, size_t size);
static const char *inet_ntop6 (const u_char *src, char *dst, size_t size);

/* char *
 * inet_ntop(af, src, dst, size)
 *  convert a network format address to presentation format.
 * return:
 *  pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *  Paul Vixie, 1996.
 */
const char *
xinet_ntop(int af, const void *src, char *dst, size_t size)
{
    switch (af) {
    case AF_INET:
        return (inet_ntop4((const u_char*)src, dst, size));
    case AF_INET6:
        return (inet_ntop6((const u_char*)src, dst, size));
    default:
        errno = EAFNOSUPPORT;
        return (NULL);
    }
    /* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *  format an IPv4 address
 * return:
 *  `dst' (as a const)
 * notes:
 *  (1) uses no statics
 *  (2) takes a u_char* not an in_addr as input
 * author:
 *  Paul Vixie, 1996.
 */
static const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
    static const char fmt[] = "%u.%u.%u.%u";
    char tmp[sizeof("255.255.255.255")+1];

    if ((size_t)snprintf(tmp, min(sizeof(tmp),size), fmt, src[0], src[1], src[2], src[3]) >= size) {
        errno = ENOSPC;
        return (NULL);
    }
    strcpy(dst, tmp);
    return (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *  convert IPv6 binary address into presentation (printable) format
 * author:
 *  Paul Vixie, 1996.
 */
static const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
    /*
     * Note that int32_t and int16_t need only be "at least" large enough
     * to contain a value of the specified size.  On some systems, like
     * Crays, there is no such thing as an integer variable with 16 bits.
     * Keep this in mind if you think this function should have been coded
     * to use pointer overlays.  All the world's not a VAX.
     */
    char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
    struct { int base, len; } best, cur;
    u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
    int i;

    /*
     * Preprocess:
     *  Copy the input (bytewise) array into a wordwise array.
     *  Find the longest run of 0x00's in src[] for :: shorthanding.
     */
    memset(words, '\0', sizeof words);
    for (i = 0; i < NS_IN6ADDRSZ; i++)
        words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
    best.base = -1;
    best.len = 0;
    cur.base = -1;
    cur.len = 0;
    for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
        if (words[i] == 0) {
            if (cur.base == -1)
                cur.base = i, cur.len = 1;
            else
                cur.len++;
        } else {
            if (cur.base != -1) {
                if (best.base == -1 || cur.len > best.len)
                    best = cur;
                cur.base = -1;
            }
        }
    }
    if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
            best = cur;
    }
    if (best.base != -1 && best.len < 2)
        best.base = -1;

    /*
     * Format the result.
     */
    tp = tmp;
    for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
        /* Are we inside the best run of 0x00's? */
        if (best.base != -1 && i >= best.base &&
                i < (best.base + best.len)) {
            if (i == best.base)
                *tp++ = ':';
            continue;
        }
        /* Are we following an initial run of 0x00s or any real hex? */
        if (i != 0)
            *tp++ = ':';
        /* Is this address an encapsulated IPv4? */
        if (i == 6 && best.base == 0 && (best.len == 6 ||
                                         (best.len == 7 && words[7] != 0x0001) ||
                                         (best.len == 5 && words[5] == 0xffff))) {
            if (!inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
                return (NULL);
            tp += strlen(tp);
            break;
        }
        tp += snprintf(tp, (tmp + sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - tp), "%x", words[i]);
    }
    /* Was it a trailing run of 0x00's? */
    if (best.base != -1 && (best.base + best.len) ==
            (NS_IN6ADDRSZ / NS_INT16SZ))
        *tp++ = ':';
    *tp++ = '\0';

    /*
     * Check for overflow, copy, and we're done.
     */
    if ((size_t)(tp - tmp) > size) {
        errno = ENOSPC;
        return (NULL);
    }
    strcpy(dst, tmp);
    return (dst);
}

#endif /* HAVE_DECL_INET_NTOP */

