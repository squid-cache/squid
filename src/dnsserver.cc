
/*
 * $Id: dnsserver.cc,v 1.42 1998/02/05 17:37:43 wessels Exp $
 *
 * DEBUG: section 0     DNS Resolver
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
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
#elif HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
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

#if HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#if HAVE_RESOLV_H
#include <resolv.h>
#endif

#include "util.h"
#include "snprintf.h"

extern int h_errno;

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

static int do_debug = 0;
static struct in_addr no_addr;

/* error messages from gethostbyname() */
static char *
my_h_msgs(int x)
{
    if (x == HOST_NOT_FOUND)
	return "Host not found (authoritative)";
    else if (x == TRY_AGAIN)
	return "Host not found (non-authoritative)";
    else if (x == NO_RECOVERY)
	return "Non recoverable errors";
    else if (x == NO_DATA || x == NO_ADDRESS)
	return "Valid name, no data record of requested type";
    else
	return "Unknown DNS problem";
}

#define REQ_SZ 512

int
main(int argc, char *argv[])
{
    char request[512];
    char msg[1024];
    const struct hostent *result = NULL;
    FILE *logfile = NULL;
    long start;
    long stop;
    char *t = NULL;
    char buf[256];
    int addr_count = 0;
    int alias_count = 0;
    int i;
    int c;

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

    while ((c = getopt(argc, argv, "vhdD")) != -1) {
	switch (c) {
	case 'v':
	    printf("dnsserver version %s\n", SQUID_VERSION);
	    exit(0);
	    break;
	case 'd':
	    snprintf(buf, 256, "dnsserver.%d.log", (int) getpid());
	    logfile = fopen(buf, "a");
	    do_debug++;
	    if (!logfile)
		fprintf(stderr, "Could not open dnsserver's log file\n");
	    break;
	case 'D':
#ifdef RES_DEFNAMES
	    _res.options |= RES_DEFNAMES;
#endif
	    break;
	case 'h':
	default:
	    fprintf(stderr, "usage: dnsserver -hvd\n");
	    exit(1);
	    break;
	}
    }

    for (;;) {
	int retry_count = 0;
	struct in_addr ip;
	memset(request, '\0', REQ_SZ);

	/* read from ipcache */
	if (fgets(request, REQ_SZ, stdin) == NULL) {
	    exit(1);
	}
	t = strrchr(request, '\n');
	if (t == NULL)		/* Ignore if no newline */
	    continue;
	*t = '\0';		/* strip NL */
	if ((t = strrchr(request, '\r')) != NULL)
	    *t = '\0';		/* strip CR */
	if (strcmp(request, "$shutdown") == 0) {
	    exit(0);
	}
	if (strcmp(request, "$hello") == 0) {
	    printf("$alive\n");
	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
	result = NULL;
	start = time(NULL);
	/* check if it's already an IP address in text form. */
	if (safe_inet_addr(request, &ip)) {
#if NO_REVERSE_LOOKUP
	    printf("$name %s\n", request);
	    printf("$h_name %s\n", request);
	    printf("$h_len %d\n", 4);
	    printf("$ipcount %d\n", 1);
	    printf("%s\n", request);
	    printf("$aliascount %d\n", 0);
	    printf("$end\n");
	    fflush(stdout);
	    continue;
#endif
	    for (;;) {
		result = gethostbyaddr((char *) &ip.s_addr, 4, AF_INET);
		if (result || h_errno != TRY_AGAIN)
		    break;
		if (++retry_count == 2)
		    break;
		sleep(2);
	    }
	} else {
	    for (;;) {
		result = gethostbyname(request);
		if (result || h_errno != TRY_AGAIN)
		    break;
		if (++retry_count == 2)
		    break;
		sleep(2);
	    }
	}
	stop = time(NULL);

	msg[0] = '\0';
	if (!result) {
	    if (h_errno == TRY_AGAIN) {
		snprintf(msg, 1024, "Name Server for domain '%s' is unavailable.\n",
		    request);
	    } else {
		snprintf(msg, 1024, "DNS Domain '%s' is invalid: %s.\n",
		    request, my_h_msgs(h_errno));
	    }
	}
	if (!result || (strlen(result->h_name) == 0)) {
	    if (logfile) {
		fprintf(logfile, "%s %d\n", request, (int) (stop - start));
		fflush(logfile);
	    }
	    printf("$fail %s\n", request);
	    printf("$message %s", msg[0] ? msg : "Unknown Error\n");
	    printf("$end\n");
	    fflush(stdout);
	    continue;
	} else {

	    printf("$name %s\n", request);
	    printf("$h_name %s\n", result->h_name);
	    printf("$h_len %d\n", result->h_length);

	    addr_count = alias_count = 0;
	    while (result->h_addr_list[addr_count] && addr_count < 255)
		++addr_count;
	    printf("$ipcount %d\n", addr_count);
	    for (i = 0; i < addr_count; i++) {
		struct in_addr addr;
		xmemcpy((char *) &addr, result->h_addr_list[i], result->h_length);
		printf("%s\n", inet_ntoa(addr));
	    }

#ifdef SEND_ALIASES
	    while ((alias_count < 255) && result->h_aliases[alias_count])
		++alias_count;
#endif
	    printf("$aliascount %d\n", alias_count);
	    for (i = 0; i < alias_count; i++) {
		printf("%s\n", result->h_aliases[i]);
	    }

#if LIBRESOLV_DNS_TTL_HACK
	    /* DNS TTL handling - bne@CareNet.hu
	     * for first try it's a dirty hack, by hacking getanswer
	     * to place th e ttl in a global variable */
	    if (_dns_ttl_ > -1)
		printf("$ttl %d\n", _dns_ttl_);
#endif

	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
    }
    /* NOTREACHED */
    return 0;
}
