
/*
 * $Id: dnsserver.cc,v 1.72 2007/12/06 18:01:53 rousskov Exp $
 *
 * DEBUG: section 0     DNS Resolver
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

#include "config.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
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
#if HAVE_NETDB_H && !defined(_SQUID_NETDB_H_)	/* protect NEXTSTEP */
#define _SQUID_NETDB_H_
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
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>	/* needs sys/time.h above it */
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
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
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

#include "util.h"

#if !defined(_SQUID_AIX_) && !defined(_SQUID_MSWIN_)
extern int h_errno;
#endif

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;		/* this is a really *dirty* hack - bne */
#endif

#ifdef _SQUID_NEXT_
/* This is a really bloody hack. frank@langen.bull.de
 * Workaround bug in gethostbyname which sets h_errno wrong
 * WARNING: This hack queries only the resolver and not NetInfo or YP
 */

struct hostent *_res_gethostbyname(char *name);
#define gethostbyname _res_gethostbyname
#endif /* _SQUID_NEXT_ */

static struct IN_ADDR no_addr;

/* error messages from gethostbyname() */
static char *
my_h_msgs(int x)
{
    if (x == HOST_NOT_FOUND)
        return (char *)"Host not found (authoritative)";
    else if (x == TRY_AGAIN)
        return (char *)"Host not found (non-authoritative)";
    else if (x == NO_RECOVERY)
        return (char *)"Non recoverable errors";
    else if (x == NO_DATA || x == NO_ADDRESS)
        return (char *)"Valid name, no data record of requested type";
    else
        return (char *)"Unknown DNS problem";
}

#define REQ_SZ 512

static void
lookup(const char *buf)
{

    const struct hostent *result = NULL;
    int reverse = 0;
    int ttl = 0;
    int retry = 0;
    int i;

    struct IN_ADDR addr;

    if (0 == strcmp(buf, "$shutdown"))
        exit(0);

    if (0 == strcmp(buf, "$hello")) {
        printf("$alive\n");
        return;
    }

    /* check if it's already an IP address in text form. */
    for (;;) {
        if (safe_inet_addr(buf, &addr)) {
            reverse = 1;
            result = gethostbyaddr((char *) &addr.s_addr, 4, AF_INET);
        } else {
            result = gethostbyname(buf);
        }

        if (NULL != result)
            break;

        if (h_errno != TRY_AGAIN)
            break;

        if (++retry == 3)
            break;

        sleep(1);
    }

    if (NULL == result) {
        if (h_errno == TRY_AGAIN) {
            printf("$fail Name Server for domain '%s' is unavailable.\n", buf);
        } else {
            printf("$fail DNS Domain '%s' is invalid: %s.\n",
                   buf, my_h_msgs(h_errno));
        }

        return;
    }

#if LIBRESOLV_DNS_TTL_HACK
    /* DNS TTL handling - bne@CareNet.hu
     * for first try it's a dirty hack, by hacking getanswer
     * to place the ttl in a global variable */
    if (_dns_ttl_ > -1)
        ttl = _dns_ttl_;

#endif

    if (reverse) {
        printf("$name %d %s\n", ttl, result->h_name);
        return;
    }

    printf("$addr %d", ttl);

    for (i = 0; NULL != result->h_addr_list[i]; i++) {
        if (32 == i)
            break;

        xmemcpy(&addr, result->h_addr_list[i], sizeof(addr));

        printf(" %s", inet_ntoa(addr));
    }

    printf("\n");
}

static void
usage(void)
{
    fprintf(stderr, "usage: dnsserver -Dhv -s nameserver\n"
            "\t-D             Enable resolver RES_DEFNAMES and RES_DNSRCH options\n"
            "\t-h             Help\n"
            "\t-v             Version\n"
            "\t-s nameserver  Specify alternate name server(s).  'nameserver'\n"
            "\t               must be an IP address, -s option may be repeated\n");
}

int
main(int argc, char *argv[])
{
    char request[512];
    char *t = NULL;
    int c;
#if HAVE_RES_INIT

    int opt_s = 0;
#if HAVE_RES_NSADDR_LIST || HAVE_RES_NS_LIST

    extern char *optarg;
#endif
#endif

    safe_inet_addr("255.255.255.255", &no_addr);

#if HAVE_RES_INIT

    res_init();
#ifdef RES_DEFAULT

    _res.options = RES_DEFAULT;
#endif
#ifdef RES_DEFNAMES

    _res.options &= ~RES_DEFNAMES;
#endif
#ifdef RES_DNSRCH

    _res.options &= ~RES_DNSRCH;
#endif
#endif

    while ((c = getopt(argc, argv, "Dhs:v")) != -1) {
        switch (c) {

        case 'D':
#ifdef RES_DEFNAMES

            _res.options |= RES_DEFNAMES;
#endif
#ifdef RES_DNSRCH

            _res.options |= RES_DNSRCH;
#endif

            break;

        case 's':
#if HAVE_RES_INIT

            if (opt_s == 0) {
                _res.nscount = 0;
                /*
                 * Setting RES_INIT here causes coredumps when -s is
                 * used with -D option.  It looks to me like setting
                 * RES_INIT is wrong.  The resolver code sets RES_INIT
                 * after calling res_init().  When we change the _res
                 * structure and set RES_INIT, some internal resolver
                 * structures get confused.             -DW 2.1.p1
                 */
#if SEEMS_WRONG

                _res.options |= RES_INIT;
#endif

                opt_s = 1;
            } else if (_res.nscount == MAXNS) {
                fprintf(stderr, "Too many -s options, only %d are allowed\n",
                        MAXNS);
                break;
            }

#if HAVE_RES_NSADDR_LIST
            _res.nsaddr_list[_res.nscount] = _res.nsaddr_list[0];

            safe_inet_addr(optarg, &_res.nsaddr_list[_res.nscount++].sin_addr);

#elif HAVE_RES_NS_LIST

            _res.ns_list[_res.nscount] = _res.ns_list[0];

            safe_inet_addr(optarg, &_res.ns_list[_res.nscount++].addr.sin_addr);

#else /* Unknown NS list format */

            fprintf(stderr, "-s is not supported on this resolver\n");

#endif
#else /* !HAVE_RES_INIT */

            fprintf(stderr, "-s is not supported on this resolver\n");

#endif /* HAVE_RES_INIT */

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

#ifdef _SQUID_MSWIN_
    {
        WSADATA wsaData;

        WSAStartup(2, &wsaData);
    }

    fflush(stderr);
#endif

    for (;;) {
        memset(request, '\0', REQ_SZ);

	if (fgets(request, REQ_SZ, stdin) == NULL) {
#ifdef _SQUID_MSWIN_
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
