/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 *  Shamelessly duplicated from the fetchmail public sources
 *  for use by the Squid Project under GNU Public License.
 *
 * Update/Maintenance History:
 *
 *    16-Aug-2007 : Copied from fetchmail 6.3.8
 *                      - added protection around libray headers
 *                      - added use of alternative name xgetnameinfo
 *                        to split from any OS-provided.
 *
 *    06-Oct-2007 : Various fixes to allow the build on MinGW
 *                      - use srtncpy instead of strlcpy
 *                      - use xinet_ntop instead of inet_ntop
 *                      - use SQUIDHOSTNAMELEN instead of MAXHOSTNAMELEN
 *
 *    13-Jan-2015 : Various fixed for C++ and MinGW native build
 *
 *  Original License and code follows.
 */
#include "squid.h"

/*  KAME: getnameinfo.c,v 1.72 2005/01/13 04:12:03 itojun Exp   */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Issues to be discussed:
 * - RFC2553 says that we should raise error on short buffer.  X/Open says
 *   we need to truncate the result.  We obey RFC2553 (and X/Open should be
 *   modified).  ipngwg rough consensus seems to follow RFC2553.  RFC3493 says
 *   nothing about it, but defines a new error code EAI_OVERFLOW which seems
 *   to be intended the code for this case.
 * - What is "local" in NI_NOFQDN?  (see comments in the code)
 * - NI_NAMEREQD and NI_NUMERICHOST conflict with each other.
 * - (KAME extension) always attach textual scopeid (fe80::1%lo0), if
 *   sin6_scope_id is filled - standardization status?
 * - what should we do if we should do getservbyport("sctp")?
 */

/*
 * Considerations about thread-safeness
 *   The code in this file is thread-safe, and so the thread-safeness of
 *   getnameinfo() depends on the property of backend functions.
 *     - getservbyport() is not thread safe for most systems we are targeting.
 *     - getipnodebyaddr() is thread safe.  However, many resolver libraries
 *       used in the function are not thread safe.
 *     - gethostbyaddr() is usually not thread safe.
 */

#if !HAVE_DECL_GETNAMEINFO

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
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
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDDEF_H
#include <stddef.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if _SQUID_WINDOWS_
#undef IN_ADDR
#include <ws2tcpip.h>
#endif

static const struct afd {
    int a_af;
    int a_addrlen;
    int a_socklen;
    int a_off;
    int a_portoff;
} afdl [] = {
#if INET6
    {   PF_INET6, sizeof(struct in6_addr), sizeof(struct sockaddr_in6),
        offsetof(struct sockaddr_in6, sin6_addr),
        offsetof(struct sockaddr_in6, sin6_port)
    },
#endif
    {   PF_INET, sizeof(struct in_addr), sizeof(struct sockaddr_in),
        offsetof(struct sockaddr_in, sin_addr),
        offsetof(struct sockaddr_in, sin_port)
    },
    {0, 0, 0, 0, 0},
};

#if INET6
static int ip6_parsenumeric __P((const struct sockaddr *, const char *, char *,
                                 size_t, int));
static int ip6_sa2str __P((const struct sockaddr_in6 *, char *, size_t, int));
#endif

int
xgetnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags)
{
    const struct afd *afd;
    struct servent *sp;
    struct hostent *hp;
    unsigned short port;
    int family, i;
    const char *addr;
    uint32_t v4a;
    char numserv[512];

    if (sa == NULL)
        return EAI_FAIL;

#if HAVE_SA_LEN /*XXX*/
    if (sa->sa_len != salen)
        return EAI_FAIL;
#endif

    family = sa->sa_family;
    for (i = 0; afdl[i].a_af; i++)
        if (afdl[i].a_af == family) {
            afd = &afdl[i];
            goto found;
        }
    return EAI_FAMILY;

found:
    if (salen != afd->a_socklen)
        return EAI_FAIL;

    /* network byte order */
    memcpy(&port, (const char *)sa + afd->a_portoff, sizeof(port));
    addr = (const char *)sa + afd->a_off;

    if (serv == NULL || servlen == 0) {
        /*
         * do nothing in this case.
         * in case you are wondering if "&&" is more correct than
         * "||" here: RFC3493 says that serv == NULL OR servlen == 0
         * means that the caller does not want the result.
         */
    } else {
        if (flags & NI_NUMERICSERV)
            sp = NULL;
        else {
            sp = getservbyport(port,
                               (flags & NI_DGRAM) ? "udp" : "tcp");
        }
        if (sp) {
            if (strlen(sp->s_name) + 1 > servlen)
                return EAI_OVERFLOW;
            xstrncpy(serv, sp->s_name, servlen);
        } else {
            snprintf(numserv, sizeof(numserv), "%u", ntohs(port));
            if (strlen(numserv) + 1 > servlen)
                return EAI_OVERFLOW;
            xstrncpy(serv, numserv, servlen);
        }
    }

    switch (sa->sa_family) {
    case AF_INET:
        v4a = (uint32_t)
              ntohl(((const struct sockaddr_in *)sa)->sin_addr.s_addr);
        if (IN_MULTICAST(v4a) || IN_EXPERIMENTAL(v4a))
            flags |= NI_NUMERICHOST;
        v4a >>= IN_CLASSA_NSHIFT;
        if (v4a == 0)
            flags |= NI_NUMERICHOST;
        break;
#if INET6
    case AF_INET6: {
        const struct sockaddr_in6 *sin6;
        sin6 = (const struct sockaddr_in6 *)sa;
        switch (sin6->sin6_addr.s6_addr[0]) {
        case 0x00:
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
                ;
            else if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
                ;
            else
                flags |= NI_NUMERICHOST;
            break;
        default:
            if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
                flags |= NI_NUMERICHOST;
            else if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
                flags |= NI_NUMERICHOST;
            break;
        }
    }
    break;
#endif
    }
    if (host == NULL || hostlen == 0) {
        /*
         * do nothing in this case.
         * in case you are wondering if "&&" is more correct than
         * "||" here: RFC3493 says that host == NULL or hostlen == 0
         * means that the caller does not want the result.
         */
    } else if (flags & NI_NUMERICHOST) {
        /* NUMERICHOST and NAMEREQD conflicts with each other */
        if (flags & NI_NAMEREQD)
            return EAI_NONAME;

        goto numeric;
    } else {
#if USE_GETIPNODEBY
        int h_error = 0;
        hp = getipnodebyaddr(addr, afd->a_addrlen, afd->a_af, &h_error);
#else
        hp = gethostbyaddr(addr, afd->a_addrlen, afd->a_af);
#if 0 // getnameinfo.c:161:9: error: variable 'h_error' set but not used
#if HAVE_H_ERRNO
        h_error = h_errno;
#else
        h_error = EINVAL;
#endif
#endif /* 0 */
#endif

        if (hp) {
#if 0
            if (flags & NI_NOFQDN) {
                /*
                 * According to RFC3493 section 6.2, NI_NOFQDN
                 * means "node name portion of the FQDN shall
                 * be returned for local hosts."  The following
                 * code tries to implement it by returning the
                 * first label (the part before the first
                 * period) of the FQDN.  However, it is not
                 * clear if this always makes sense, since the
                 * given address may be outside of "local
                 * hosts."  Due to the unclear description, we
                 * disable the code in this implementation.
                 */
                char *p;
                p = strchr(hp->h_name, '.');
                if (p)
                    *p = '\0';
            }
#endif
            if (strlen(hp->h_name) + 1 > hostlen) {
#if USE_GETIPNODEBY
                freehostent(hp);
#endif
                return EAI_OVERFLOW;
            }
            xstrncpy(host, hp->h_name, hostlen);
#if USE_GETIPNODEBY
            freehostent(hp);
#endif
        } else {
            if (flags & NI_NAMEREQD)
                return EAI_NONAME;

numeric:
            switch (afd->a_af) {
#if INET6
            case AF_INET6: {
                int error;

                if ((error = ip6_parsenumeric(sa, addr, host,
                                              hostlen,
                                              flags)) != 0)
                    return(error);
                break;
            }
#endif
            default:
                if (inet_ntop(afd->a_af, addr, host,
                              hostlen) == NULL)
                    return EAI_SYSTEM;
                break;
            }
        }
    }
    return(0);
}

#if INET6
static int
ip6_parsenumeric(sa, addr, host, hostlen, flags)
const struct sockaddr *sa;
const char *addr;
char *host;
size_t hostlen;
int flags;
{
    int numaddrlen;
    char numaddr[512];

    if (inet_ntop(AF_INET6, addr, numaddr, sizeof(numaddr)) == NULL)
        return EAI_SYSTEM;

    numaddrlen = strlen(numaddr);
    if (numaddrlen + 1 > hostlen) /* don't forget terminator */
        return EAI_OVERFLOW;
    xstrncpy(host, numaddr, hostlen);

    if (((const struct sockaddr_in6 *)sa)->sin6_scope_id) {
        char zonebuf[SQUIDHOSTNAMELEN];
        int zonelen;

        zonelen = ip6_sa2str(
                      (const struct sockaddr_in6 *)(const void *)sa,
                      zonebuf, sizeof(zonebuf), flags);
        if (zonelen < 0)
            return EAI_OVERFLOW;
        if (zonelen + 1 + numaddrlen + 1 > hostlen)
            return EAI_OVERFLOW;

        /* construct <numeric-addr><delim><zoneid> */
        memcpy(host + numaddrlen + 1, zonebuf,
               (size_t)zonelen);
        host[numaddrlen] = SCOPE_DELIMITER;
        host[numaddrlen + 1 + zonelen] = '\0';
    }

    return 0;
}

/* ARGSUSED */
static int
ip6_sa2str(sa6, buf, bufsiz, flags)
const struct sockaddr_in6 *sa6;
char *buf;
size_t bufsiz;
int flags;
{
    unsigned int ifindex;
    const struct in6_addr *a6;
    int n;

    ifindex = (unsigned int)sa6->sin6_scope_id;
    a6 = &sa6->sin6_addr;

#if NI_NUMERICSCOPE
    if ((flags & NI_NUMERICSCOPE) != 0) {
        n = snprintf(buf, bufsiz, "%u", sa6->sin6_scope_id);
        if (n < 0 || n >= bufsiz)
            return -1;
        else
            return n;
    }
#endif

    /* if_indextoname() does not take buffer size.  not a good api... */
    if ((IN6_IS_ADDR_LINKLOCAL(a6) || IN6_IS_ADDR_MC_LINKLOCAL(a6) ||
            IN6_IS_ADDR_MC_NODELOCAL(a6)) && bufsiz >= IF_NAMESIZE) {
        char *p = if_indextoname(ifindex, buf);
        if (p)
            return (strlen(p));
    }

    /* last resort */
    n = snprintf(buf, bufsiz, "%u", sa6->sin6_scope_id);
    if (n < 0 || n >= bufsiz)
        return -1;
    else
        return n;
}
#endif /* INET6 */
#endif /* HAVE_DECL_GETNAMEINFO */

