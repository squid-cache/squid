
/*
 * $Id: dnsserver.cc,v 1.18 1996/08/31 06:40:18 wessels Exp $
 *
 * DEBUG: section 0     DNS Resolver
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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
#if HAVE_MALLOC_H && !defined(_SQUID_FREEBSD_) && !defined(_SQUID_NEXT_)
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

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

#include "util.h"

extern int h_errno;

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;		/* this is a really *dirty* hack - bne */
#endif

int do_debug = 0;

/* error messages from gethostbyname() */
#define my_h_msgs(x) (\
	((x) == HOST_NOT_FOUND) ? \
		"Host not found (authoritative)" : \
	((x) == TRY_AGAIN) ? \
		"Host not found (non-authoritative)" : \
	((x) == NO_RECOVERY) ? \
		"Non recoverable errors" : \
	((x) == NO_DATA) ? \
		"Valid name, no data record of requested type" : \
	((x) == NO_ADDRESS) ? \
		"No address, look for MX record" : \
		"Unknown DNS problem")

/* 
 * Modified to use UNIX domain sockets between squid and the dnsservers to
 * save an FD per DNS server, Hong Mei, USC.
 * 
 * Before forking a dnsserver, squid creates listens on a UNIX domain
 * socket.  After the fork(), squid closes its end of the rendevouz socket
 * but then immediately connects to it to establish the connection to the
 * dnsserver process.  We use AF_UNIX to prevent other folks from
 * connecting to our little dnsservers after we fork but before we connect
 * to them.
 * 
 * Squid creates UNIX domain sockets named dns.PID.NN, e.g. dns.19215.11
 * 
 * In ipcache_init():
 *       . dnssocket = ipcache_opensocket(Config.Program.dnsserver)
 *       . dns_child_table[i]->inpipe = dnssocket
 *       . dns_child_table[i]->outpipe = dnssocket
 * 
 * The dnsserver inherits socket(socket_from_ipcache) from squid which it
 * uses to rendevouz with.  The child takes responsibility for cleaning up
 * the UNIX domain pathnames by setting a few signal handlers.
 * 
 */

int main(argc, argv)
     int argc;
     char *argv[];
{
    char request[256];
    char msg[256];
    struct hostent *result = NULL;
    FILE *logfile = NULL;
    long start;
    long stop;
    char *t = NULL;
    char buf[256];
    int socket_from_cache, fd;
    int addr_count = 0;
    int alias_count = 0;
    int i;
    char *dnsServerPathname = NULL;
    int dnsServerTCP = 0;
    int c;
    extern char *optarg;

#if HAVE_RES_INIT
    res_init();
#ifdef RES_DEFNAMES
    _res.options &= ~RES_DEFNAMES;
#endif
#ifdef RES_DNSRCH
    _res.options &= ~RES_DNSRCH;
#endif
#endif

    while ((c = getopt(argc, argv, "vhdtp:")) != -1) {
	switch (c) {
	case 'v':
	case 'h':
	    printf("dnsserver version %s\n", SQUID_VERSION);
	    exit(0);
	    break;
	case 'd':
	    sprintf(buf, "dnsserver.%d.log", (int) getpid());
	    logfile = fopen(buf, "a");
	    do_debug++;
	    if (!logfile)
		fprintf(stderr, "Could not open dnsserver's log file\n");
	    break;
	case 'p':
	    dnsServerPathname = xstrdup(optarg);
	    break;
	case 't':
	    dnsServerTCP = 1;
	    break;
	default:
	    fprintf(stderr, "usage: dnsserver -h -d -p socket-filename\n");
	    exit(1);
	    break;
	}
    }

    socket_from_cache = 3;

    /* accept DNS look up from ipcache */
    if (dnsServerPathname || dnsServerTCP) {
	fd = accept(socket_from_cache, NULL, NULL);
	if (dnsServerPathname)
	    unlink(dnsServerPathname);
	if (fd < 0) {
	    fprintf(stderr, "dnsserver: accept: %s\n", xstrerror());
	    exit(1);
	}
	close(socket_from_cache);

	/* point stdout to fd */
	dup2(fd, 1);
	dup2(fd, 0);
	if (fd > 1)
	    close(fd);
    }
    while (1) {
	int retry_count = 0;
	int addrbuf;
	memset(request, '\0', 256);

	/* read from ipcache */
	if (fgets(request, 255, stdin) == NULL)
	    exit(1);
	if ((t = strrchr(request, '\n')) != NULL)
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
	if (inet_addr(request) != INADDR_NONE) {
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
	    addrbuf = inet_addr(request);
	    for (;;) {
		result = gethostbyaddr((char *) &addrbuf, 4, AF_INET);
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
		sprintf(msg, "Name Server for domain '%s' is unavailable.\n",
		    request);
	    } else {
		sprintf(msg, "DNS Domain '%s' is invalid: %s.\n",
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
}
