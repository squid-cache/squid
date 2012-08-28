/*
 * DEBUG: section 00    DNS Resolver Daemon
 * AUTHOR: Harvest Derived
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

#include "squid.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ERRNO_H
#include <errno.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_TIME_H
#include <time.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
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
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_LIBC_H
#include <libc.h>
#endif
#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif

/**
 \defgroup dnsserver dnsserver
 \ingroup ExternalPrograms
 \par
    Because the standard gethostbyname() library call
    blocks, Squid must use external processes to actually make
    these calls.  Typically there will be ten dnsserver
    processes spawned from Squid.  Communication occurs via
    TCP sockets bound to the loopback interface.  The functions
    in dns.cc are primarily concerned with starting and
    stopping the dnsservers.  Reading and writing to and from
    the dnsservers occurs in the \link IPCacheAPI IP\endlink and
    \link FQDNCacheAPI FQDN\endlink cache modules.

 \section dnsserverInterface Command Line Interface
 \verbatim
usage: dnsserver -Dhv -s nameserver
	-D             Enable resolver RES_DEFNAMES and RES_DNSRCH options
	-h             Help
	-v             Version
	-s nameserver  Specify alternate name server(s).  'nameserver'
	               must be an IP address, -s option may be repeated
 \endverbatim
 */

#if LIBRESOLV_DNS_TTL_HACK
/// \ingroup dnsserver
extern int _dns_ttl_;		/* this is a really *dirty* hack - bne */
#endif

/*
 * res_init() is a macro re-definition of __res_init on: Debian
 */
#if !defined(HAVE_RES_INIT) && defined(HAVE___RES_INIT)
#ifndef res_init
#define res_init  __res_init
#endif
#define HAVE_RES_INIT   HAVE___RES_INIT
#endif

/// \ingroup dnsserver
#define REQ_SZ 512

/**
 \ingroup dnsserver
 */
static void
lookup(const char *buf)
{
    int ttl = 0;
    int retry = 0;
    unsigned int i = 0;
    char ntoabuf[256];
    struct addrinfo hints;
    struct addrinfo *AI = NULL;
    struct addrinfo *aiptr = NULL;
    struct addrinfo *prev_addr = NULL;
    int res = 0;

    if (0 == strcmp(buf, "$shutdown"))
        exit(0);

    if (0 == strcmp(buf, "$hello")) {
        printf("$alive\n");
        return;
    }

    /* check if it's already an IP address in text form. */
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST; // only succeed if its numeric.
    const bool isDomain = (getaddrinfo(buf,NULL,&hints,&AI) != 0);

    // reset for real lookup
    if (AI != NULL) {
        freeaddrinfo(AI);
        AI = NULL;
    }

    // resolve the address/name
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_CANONNAME;
    for (;;) {
        if (AI != NULL) {
            freeaddrinfo(AI);
            AI = NULL;
        }

        if ( 0 == (res = getaddrinfo(buf,NULL,&hints,&AI)) )
            break;

        if (res != EAI_AGAIN)
            break;

        if (++retry == 3)
            break;

        sleep(1);
    }

    if (isDomain) {
        /* its a domain name. Use the forward-DNS lookup already done */

        if (res == 0) {
#if LIBRESOLV_DNS_TTL_HACK
            /* DNS TTL handling - bne@CareNet.hu
             * for first try it's a dirty hack, by hacking getanswer
             * to place the ttl in a global variable */
            if (_dns_ttl_ > -1)
                ttl = _dns_ttl_;
#endif
            printf("$addr %d", ttl);

            i = 0;
            aiptr = AI;
            while (NULL != aiptr && 32 >= i) {
                memset(ntoabuf, 0, sizeof(ntoabuf));

                /* getaddrinfo given a host has a nasty tendency to return duplicate addr's */
                /* BUT sorted fortunately, so we can drop most of them easily */
                if ( prev_addr &&
                        prev_addr->ai_family==aiptr->ai_family &&
                        memcmp(aiptr->ai_addr, prev_addr->ai_addr, aiptr->ai_addrlen)==0
                   ) {
                    prev_addr = aiptr;
                    aiptr = aiptr->ai_next;
                    continue;
                } else {
                    prev_addr = aiptr;
                }

                /* annoying inet_ntop breaks the nice code by requiring the in*_addr */
                switch (aiptr->ai_family) {
                case AF_INET:
                    inet_ntop(aiptr->ai_family, &((struct sockaddr_in*)aiptr->ai_addr)->sin_addr, ntoabuf, sizeof(ntoabuf));
                    break;
                case AF_INET6:
                    inet_ntop(aiptr->ai_family, &((struct sockaddr_in6*)aiptr->ai_addr)->sin6_addr, ntoabuf, sizeof(ntoabuf));
                    break;
                default:
                    aiptr = aiptr->ai_next;
                    continue;
                }
                printf(" %s", ntoabuf);
                ++i;
                aiptr = aiptr->ai_next;
            }

            prev_addr=NULL;
            printf("\n");
        }
    } else { /* its an IPA in text form. perform rDNS */
        /* You'd expect getaddrinfo given AI_CANONNAME would do a lookup on
         * missing FQDN. But no, it only copies the input string to that
         * position regardless of its content.
         */
        if (NULL != AI && NULL != AI->ai_addr) {
            for (;;) {
                if ( 0 == (res = getnameinfo(AI->ai_addr, AI->ai_addrlen, ntoabuf, sizeof(ntoabuf), NULL,0,0)) )
                    break;

                if (res != EAI_AGAIN)
                    break;

                if (++retry == 3)
                    break;

                sleep(1);
            }
        }

        if (res == 0) {
#if LIBRESOLV_DNS_TTL_HACK
            /* DNS TTL handling - bne@CareNet.hu
             * for first try it's a dirty hack, by hacking getanswer
             * to place the ttl in a global variable */
            if (_dns_ttl_ > -1)
                ttl = _dns_ttl_;
#endif

            printf("$name %d %s\n", ttl, ntoabuf);
        }
    }

    switch (res) {
    case 0:
        /* no error. */
        break;

    case EAI_AGAIN:
        printf("$fail Name Server for domain '%s' is unavailable.\n", buf);
        break;

    case EAI_FAIL:
        printf("$fail DNS Domain/IP '%s' does not exist: %s.\n", buf, gai_strerror(res));
        break;

#if defined(EAI_NODATA) || defined(EAI_NONAME)
#if EAI_NODATA
        /* deprecated. obsolete on some OS */
    case EAI_NODATA:
#endif
#if EAI_NONAME
    case EAI_NONAME:
#endif
        printf("$fail DNS Domain/IP '%s' exists without any FQDN/IPs: %s.\n", buf, gai_strerror(res));
        break;
#endif
    default:
        printf("$fail A system error occured looking up Domain/IP '%s': %s.\n", buf, gai_strerror(res));
    }

    if (AI != NULL)
        freeaddrinfo(AI);
}

/**
 \ingroup dnsserver
 */
static void
usage(void)
{
    fprintf(stderr, "usage: dnsserver -hv -s nameserver\n"
            "\t-h             Help\n"
            "\t-v             Version\n"
            "\t-s nameserver  Specify alternate name server(s).  'nameserver'\n"
            "\t               must be an IPv4 address, -s option may be repeated\n"
           );
}

#if defined(_SQUID_RES_NSADDR6_LARRAY)
/// \ingroup dnsserver
#define _SQUID_RES_NSADDR6_LIST(i)	_SQUID_RES_NSADDR6_LARRAY[i].sin6_addr
#endif
#if defined(_SQUID_RES_NSADDR6_LPTR)
/// \ingroup dnsserver
#define _SQUID_RES_NSADDR6_LIST(i)	_SQUID_RES_NSADDR6_LPTR[i]->sin6_addr
#endif

/**
 * \ingroup dnsserver
 *
 * Override the system DNS nameservers with some local ones.
 * Equivalent to the bind res_setservers() call but for any
 * system where we can find the needed _res fields.
 */
void
squid_res_setservers(int reset)
{
#if _SQUID_FREEBSD_ && defined(_SQUID_RES_NSADDR6_COUNT)
    /* Only seems to be valid on FreeBSD 5.5 where _res_ext was provided without an ns6addr counter! */
    /* Gone again on FreeBSD 6.2 along with _res_ext itself in any form. */
    int ns6count = 0;
#endif
#if HAVE_RES_INIT && defined(_SQUID_RES_NSADDR_LIST)
    extern char *optarg;
#endif

#if HAVE_RES_INIT && (defined(_SQUID_RES_NSADDR_LIST) || defined(_SQUID_RES_NSADDR6_LIST))

    if (reset == 0) {
#if defined(_SQUID_RES_NSADDR_COUNT)
        _SQUID_RES_NSADDR_COUNT = 0;
        /* because I don't trust the nscount super-count entirely, make sure these are ALL invalid */
        memset(_SQUID_RES_NSADDR_LIST, 0, sizeof(struct sockaddr_in)*MAXNS);
#endif
#if defined(_SQUID_RES_NSADDR6_COUNT)
        _SQUID_RES_NSADDR6_COUNT = 0;
#endif
    }

    /* AYJ:
     *  I experimented with all the permutations of mixed/unmixed nscount/nscount6 IPv4/IPv6/Both/invalid
     *
     *  I'm not sure if splitting them really helps.
     *  I've seen no evidence of IPv4 resolver *ever* being used when some IPv6 are set (or not even)
     *  BUT, have seen segfault when IPv4 is added to NSADDR6 list (_res._u._ext).
     *  It also appears to not do ANY lookup when _res.nscount==0.
     *
     *  BUT, even if _res.nsaddrs is memset to NULL, it resolves IFF IPv6 set in _ext.
     *
     *  SO, am splitting the IPv4/v6 into the seperate _res fields
     *      and making nscount a total of IPv4+IPv6 /w nscount6 the IPv6 sub-counter
     *	ie. nscount = count(NSv4)+count(NSv6) & nscount6 = count(NSv6)
     *
     * If ANYONE knows better please let us know.
     */
    struct addrinfo hints;
    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST; // prevent repeated DNS lookups!
    struct addrinfo *AI = NULL;
    if ( getaddrinfo(optarg, NULL, &hints, &AI) != 0) {
        fprintf(stderr, "%s appears to be a bad nameserver FQDN/IP.\n",optarg);
    } else if ( AI->ai_family == AF_INET ) {
        if (_SQUID_RES_NSADDR_COUNT == MAXNS) {
            fprintf(stderr, "Too many -s options, only %d are allowed\n", MAXNS);
        } else {
            _SQUID_RES_NSADDR_LIST[_SQUID_RES_NSADDR_COUNT] = _SQUID_RES_NSADDR_LIST[0];
            memcpy(&_SQUID_RES_NSADDR_LIST[_SQUID_RES_NSADDR_COUNT++].sin_addr, &((struct sockaddr_in*)AI->ai_addr)->sin_addr, sizeof(struct in_addr));
        }
    } else if ( AI->ai_family == AF_INET6 ) {
#if USE_IPV6 && defined(_SQUID_RES_NSADDR6_LIST)
        /* because things NEVER seem to resolve in tests without _res.nscount being a total. */
        if (_SQUID_RES_NSADDR_COUNT == MAXNS) {
            fprintf(stderr, "Too many -s options, only %d are allowed\n", MAXNS);
        } else {
            ++ _SQUID_RES_NSADDR_COUNT;
            memcpy(&_SQUID_RES_NSADDR6_LIST(_SQUID_RES_NSADDR6_COUNT++), &((struct sockaddr_in6*)AI->ai_addr)->sin6_addr, sizeof(struct in6_addr));
        }
#else
        fprintf(stderr, "IPv6 nameservers not supported on this resolver\n");
#endif
    }
    if (AI != NULL)
        freeaddrinfo(AI);

#else /* !HAVE_RES_INIT || !defined(_SQUID_RES_NSADDR_LIST) */

    fprintf(stderr, "-s is not supported on this resolver\n");

#endif /* HAVE_RES_INIT */
}

/**
 * \ingroup dnsserver
 *
 * This is the external dnsserver process.
 */
int
main(int argc, char *argv[])
{
    char request[512];
    char *t = NULL;
    int c;
    int opt_s = 0;

#if HAVE_RES_INIT
    res_init();
#endif

#if USE_IPV6
    /* perform AAAA lookups *before* A lookups in IPv6 mode. */
    _res.options |= RES_USE_INET6;
#endif

    while ((c = getopt(argc, argv, "Dhs:v")) != -1) {
        switch (c) {

        case 'D':
            fprintf(stderr, "-D is now default behaviour from this tool.\n");
            break;

        case 's':
            squid_res_setservers(opt_s);
            opt_s = 1;
            break;

        case 'v':
            printf("dnsserver version %s\n", VERSION);

            exit(0);

            break;

        case 'h':

        default:
            usage();

            exit(1);

            break;
        }
    }

#if _SQUID_MSWIN_
    {
        WSADATA wsaData;

        WSAStartup(2, &wsaData);
    }

    fflush(stderr);
#endif

    for (;;) {
        memset(request, '\0', REQ_SZ);

        if (fgets(request, REQ_SZ, stdin) == NULL) {
#if _SQUID_MSWIN_
            WSACleanup();
#endif
            exit(1);
        }

        t = strrchr(request, '\n');

        if (t == NULL)		/* Ignore if no newline */
            continue;

        *t = '\0';		/* strip NL */

        if ((t = strrchr(request, '\r')) != NULL)
            *t = '\0';		/* strip CR */

        lookup(request);

        fflush(stdout);
    }

    /* NOTREACHED */
    return 0;
}
