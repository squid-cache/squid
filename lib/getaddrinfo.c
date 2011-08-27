/*
 *  Shamelessly duplicated from the fetchmail public sources
 *  for use by the Squid Project under GNU Public License.
 *
 * Update/Maintenance History:
 *
 *    15-Aug-2007 : Copied from fetchmail 6.3.8
 *			- added protection around libray headers
 *
 *    16-Aug-2007 : Altered configure checks
 *                  Un-hacked slightly to use system gethostbyname()
 *
 *    06-Oct-2007 : Various fixes to allow the build on MinGW
 *
 * Squid CVS $Id$
 *
 *  Original License and code follows.
 */
#include "config.h"

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

/* An emulation of the RFC 2553 / Posix getaddrinfo resolver interface.
 */

#ifndef HAVE_GETADDRINFO

/* Need to turn off Posix features in glibc to build this */
#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
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
#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include "getaddrinfo.h"
#include "inet_pton.h"

static struct addrinfo *
dup_addrinfo (struct addrinfo *info, void *addr, size_t addrlen) {
    struct addrinfo *ret;

    ret = malloc (sizeof (struct addrinfo));
    if (ret == NULL)
        return NULL;
    memcpy (ret, info, sizeof (struct addrinfo));
    ret->ai_addr = malloc (addrlen);
    if (ret->ai_addr == NULL) {
        free (ret);
        return NULL;
    }
    memcpy (ret->ai_addr, addr, addrlen);
    ret->ai_addrlen = addrlen;
    return ret;
}

int
xgetaddrinfo (const char *nodename, const char *servname,
              const struct addrinfo *hints, struct addrinfo **res)
{
    struct hostent *hp;
    struct servent *servent;
    const char *socktype;
    int port;
    struct addrinfo hint, result;
    struct addrinfo *ai, *sai, *eai;
    char **addrs;

    if (servname == NULL && nodename == NULL)
        return EAI_NONAME;

    memset (&result, 0, sizeof result);

    /* default for hints */
    if (hints == NULL) {
        memset (&hint, 0, sizeof hint);
        hint.ai_family = PF_UNSPEC;
        hints = &hint;
    }

    if (servname == NULL)
        port = 0;
    else {
        /* check for tcp or udp sockets only */
        if (hints->ai_socktype == SOCK_STREAM)
            socktype = "tcp";
        else if (hints->ai_socktype == SOCK_DGRAM)
            socktype = "udp";
        else
            return EAI_SERVICE;
        result.ai_socktype = hints->ai_socktype;

        /* Note: maintain port in host byte order to make debugging easier */
        if (isdigit (*servname))
            port = strtol (servname, NULL, 10);
        else if ((servent = getservbyname (servname, socktype)) != NULL)
            port = ntohs (servent->s_port);
        else
            return EAI_NONAME;
    }

    /* if nodename == NULL refer to the local host for a client or any
       for a server */
    if (nodename == NULL) {
        struct sockaddr_in sin;

        /* check protocol family is PF_UNSPEC or PF_INET - could try harder
           for IPv6 but that's more code than I'm prepared to write */
        if (hints->ai_family == PF_UNSPEC || hints->ai_family == PF_INET)
            result.ai_family = AF_INET;
        else
            return EAI_FAMILY;

        sin.sin_family = result.ai_family;
        sin.sin_port = htons (port);
        if (hints->ai_flags & AI_PASSIVE)
            sin.sin_addr.s_addr = htonl (INADDR_ANY);
        else
            sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
        /* Duplicate result and addr and return */
        *res = dup_addrinfo (&result, &sin, sizeof sin);
        return (*res == NULL) ? EAI_MEMORY : 0;
    }

    /* If AI_NUMERIC is specified, use xinet_pton to translate numbers and
       dots notation. */
    if (hints->ai_flags & AI_NUMERICHOST) {
        struct sockaddr_in sin;

        /* check protocol family is PF_UNSPEC or PF_INET */
        if (hints->ai_family == PF_UNSPEC || hints->ai_family == PF_INET)
            result.ai_family = AF_INET;
        else
            return EAI_FAMILY;

        sin.sin_family = result.ai_family;
        sin.sin_port = htons (port);
        if (xinet_pton(result.ai_family, nodename, &sin.sin_addr))
            return EAI_NONAME;
        sin.sin_addr.s_addr = inet_addr (nodename);
        /* Duplicate result and addr and return */
        *res = dup_addrinfo (&result, &sin, sizeof sin);
        return (*res == NULL) ? EAI_MEMORY : 0;
    }

#if HAVE_H_ERRNO
    h_errno = 0;
#endif
    errno = 0;
    hp = gethostbyname(nodename);
    if (hp == NULL) {
#ifdef EAI_SYSTEM
        if (errno != 0) {
            return EAI_SYSTEM;
        }
#endif
        switch (h_errno) {
        case HOST_NOT_FOUND:
            return EAI_NODATA;
        case NO_DATA:
            return EAI_NODATA;
#if defined(NO_ADDRESS) && NO_ADDRESS != NO_DATA
        case NO_ADDRESS:
            return EAI_NODATA;
#endif
        case NO_RECOVERY:
            return EAI_FAIL;
        case TRY_AGAIN:
            return EAI_AGAIN;
        default:
            return EAI_FAIL;
        }
        return EAI_FAIL;
    }

    /* Check that the address family is acceptable.
     */
    switch (hp->h_addrtype) {
    case AF_INET:
        if (!(hints->ai_family == PF_UNSPEC || hints->ai_family == PF_INET))
            return EAI_FAMILY;
        break;
    case AF_INET6:
        if (!(hints->ai_family == PF_UNSPEC || hints->ai_family == PF_INET6))
            return EAI_FAMILY;
        break;
    default:
        return EAI_FAMILY;
    }

    /* For each element pointed to by hp, create an element in the
       result linked list. */
    sai = eai = NULL;
    for (addrs = hp->h_addr_list; *addrs != NULL; addrs++) {
        struct sockaddr sa;
        size_t addrlen;

        if (hp->h_length < 1)
            continue;
        sa.sa_family = hp->h_addrtype;
        switch (hp->h_addrtype) {
        case AF_INET:
            ((struct sockaddr_in *) &sa)->sin_port = htons (port);
            memcpy (&((struct sockaddr_in *) &sa)->sin_addr,
                    *addrs, hp->h_length);
            addrlen = sizeof (struct sockaddr_in);
            break;
        case AF_INET6:
#if SIN6_LEN
            ((struct sockaddr_in6 *) &sa)->sin6_len = hp->h_length;
#endif
            ((struct sockaddr_in6 *) &sa)->sin6_port = htons (port);
            memcpy (&((struct sockaddr_in6 *) &sa)->sin6_addr,
                    *addrs, hp->h_length);
            addrlen = sizeof (struct sockaddr_in6);
            break;
        default:
            continue;
        }

        result.ai_family = hp->h_addrtype;
        ai = dup_addrinfo (&result, &sa, addrlen);
        if (ai == NULL) {
            xfreeaddrinfo (sai);
            return EAI_MEMORY;
        }
        if (sai == NULL)
            sai = ai;
        else
            eai->ai_next = ai;
        eai = ai;
    }

    if (sai == NULL) {
        return EAI_NODATA;
    }

    if (hints->ai_flags & AI_CANONNAME) {
        sai->ai_canonname = malloc (strlen (hp->h_name) + 1);
        if (sai->ai_canonname == NULL) {
            xfreeaddrinfo (sai);
            return EAI_MEMORY;
        }
        strcpy (sai->ai_canonname, hp->h_name);
    }

    *res = sai;
    return 0;
}

void
xfreeaddrinfo (struct addrinfo *ai)
{
    struct addrinfo *next;

    while (ai != NULL) {
        next = ai->ai_next;
        if (ai->ai_canonname != NULL)
            free (ai->ai_canonname);
        if (ai->ai_addr != NULL)
            free (ai->ai_addr);
        free (ai);
        ai = next;
    }
}

const char *
xgai_strerror (int ecode)
{
    static const char *eai_descr[] = {
        "no error",
        "address family for nodename not supported",	/* EAI_ADDRFAMILY */
        "temporary failure in name resolution",		/* EAI_AGAIN */
        "invalid value for ai_flags",	 		/* EAI_BADFLAGS */
        "non-recoverable failure in name resolution",	/* EAI_FAIL */
        "ai_family not supported",			/* EAI_FAMILY */
        "memory allocation failure",			/* EAI_MEMORY */
        "no address associated with nodename",		/* EAI_NODATA */
        "nodename nor servname provided, or not known",	/* EAI_NONAME */
        "servname not supported for ai_socktype",		/* EAI_SERVICE */
        "ai_socktype not supported",			/* EAI_SOCKTYPE */
        "system error returned in errno",			/* EAI_SYSTEM */
        "argument buffer overflow",			/* EAI_OVERFLOW */
    };

    if (ecode < 0 || ecode > (int) (sizeof eai_descr/ sizeof eai_descr[0]))
        return "unknown error";
    return eai_descr[ecode];
}

#endif /* HAVE_GETADDRINFO */
