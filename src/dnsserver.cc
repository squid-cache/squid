static char rcsid[] = "$Id: dnsserver.cc,v 1.2 1996/02/23 05:41:21 wessels Exp $";
/*
 *  File:         dnsserver.c
 *  Description:  dnsserver process for non-blocking DNS lookup.
 *  Author:       Anawat Chankhunthod
 *  Created:
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>

#include "util.h"

extern int h_errno;

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
 * Modified to use UNIX domain sockets between cached and the dnsservers to
 * save an FD per DNS server, Hong Mei, USC.
 * 
 * Before forking a dnsserver, cached creates listens on a UNIX domain
 * socket.  After the fork(), cached closes its end of the rendevouz socket
 * but then immediately connects to it to establish the connection to the
 * dnsserver process.  We use AF_UNIX to prevent other folks from
 * connecting to our little dnsservers after we fork but before we connect
 * to them.
 * 
 * Cached creates UNIX domain sockets named dns.PID.NN, e.g. dns.19215.11
 * 
 * In ipcache_init():
 *       . dnssocket = ipcache_opensocket(getDnsProgram())
 *       . dns_child_table[i]->inpipe = dnssocket
 *       . dns_child_table[i]->outpipe = dnssocket
 * 
 * The dnsserver inherits socket(socket_from_ipcache) from cached which it
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
    int a1, a2, a3, a4;
    int addr_count = 0;
    int alias_count = 0;
    int i;
    char *dnsServerPathname = NULL;
    int c;
    extern char *optarg;

    while ((c = getopt(argc, argv, "vhdp:")) != -1)
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
	default:
	    fprintf(stderr, "usage: dnsserver -h -d -p socket-filename\n");
	    exit(1);
	    break;
	}

    socket_from_cache = 3;

    /* accept DNS look up from ipcache */
    if (dnsServerPathname) {
	fd = accept(socket_from_cache, (struct sockaddr *) 0, (int *) 0);
	unlink(dnsServerPathname);
	if (fd < 0) {
	    fprintf(stderr, "dnsserver: accept: %s\n", xstrerror());
	    exit(1);
	}
	close(socket_from_cache);

	/* point stdout to fd */
	dup2(fd, 1);
	dup2(fd, 0);
	close(fd);
    }
    while (1) {
	memset(request, '\0', 256);

	/* read from ipcache */
	if (fgets(request, 255, stdin) == (char *) NULL)
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
	/* check if it's already an IP address in text form. */
	if (sscanf(request, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) == 4) {
	    printf("$name %s\n", request);
	    printf("$h_name %s\n", request);
	    printf("$h_len %d\n", 4);
	    printf("$ipcount %d\n", 1);
	    printf("%s\n", request);
	    printf("$aliascount %d\n", 0);
	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
	start = time(NULL);
	result = gethostbyname(request);
	if (!result) {
	    if (h_errno == TRY_AGAIN) {
		sleep(2);
		result = gethostbyname(request);	/* try a little harder */
	    }
	}
	stop = time(NULL);

	msg[0] = '\0';
	if (!result) {
	    if (h_errno == TRY_AGAIN) {
		sprintf(msg, "Name Server for domain '%s' is unavailable.",
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
	    printf("$message %s\n", msg[0] ? msg : "Unknown Error");
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
		memcpy((char *) &addr, result->h_addr_list[i], result->h_length);
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

	    printf("$end\n");
	    fflush(stdout);
	    continue;
	}
    }

    exit(0);
    /*NOTREACHED */
}
