/*
 * $Id: client.cc,v 1.48 1998/01/06 00:27:56 wessels Exp $
 *
 * DEBUG: section 0     WWW Client
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

#include "squid.h"

#ifndef BUFSIZ
#define BUFSIZ 8192
#endif

/* Local functions */
static int client_comm_connect(int, char *, u_short, struct timeval *);
static void usage(const char *progname);
static int Now(struct timeval *);
static SIGHDLR catch;

static void
usage(const char *progname)
{
    fprintf(stderr,
	"Usage: %s [-ars] [-i IMS] [-h host] [-p port] [-m method] [-t count] [-I ping-interval] url\n"
	"Options:\n"
	"    -a           Do NOT include Accept: header.\n"
	"    -r           Force cache to reload URL.\n"
	"    -s           Silent.  Do not print data to stdout.\n"
	"    -i IMS       If-Modified-Since time (in Epoch seconds).\n"
	"    -h host      Retrieve URL from cache on hostname.  Default is localhost.\n"
	"    -p port      Port number of cache.  Default is %d.\n"
	"    -m method    Request method, default is GET.\n"
	"    -t count     Trace count cache-hops\n"
	"    -g count     Ping mode, \"count\" iterations (0 to loop until interrupted).\n"
	"    -I interval  Ping interval in seconds (default 1 second).\n",
	progname, CACHE_HTTP_PORT);
    exit(1);
}

static int interrupted = 0;
int
main(int argc, char *argv[])
{
    int conn, c, len, bytesWritten;
    int port, to_stdout, reload;
    int ping, pcount;
    int keep_alive = 0;
    int opt_noaccept = 0;
    char url[BUFSIZ], msg[BUFSIZ], buf[BUFSIZ], hostname[BUFSIZ];
    const char *method = "GET";
    extern char *optarg;
    time_t ims = 0;
    int max_forwards = -1;
    struct timeval tv1, tv2;
    int i = 0, loops;
    long ping_int;
    long ping_min = 0, ping_max = 0, ping_sum = 0, ping_mean = 0;

    /* set the defaults */
    strcpy(hostname, "localhost");
    port = CACHE_HTTP_PORT;
    to_stdout = 1;
    reload = 0;
    ping = 0;
    pcount = 0;
    ping_int = 1 * 1000;

    if (argc < 2) {
	usage(argv[0]);		/* need URL */
    } else if (argc >= 2) {
	strcpy(url, argv[argc - 1]);
	if (url[0] == '-')
	    usage(argv[0]);
	while ((c = getopt(argc, argv, "ah:i:km:p:rst:g:I:?")) != -1)
	    switch (c) {
	    case 'a':
		opt_noaccept = 1;
		break;
	    case 'h':		/* host:arg */
		if (optarg != NULL)
		    strcpy(hostname, optarg);
		break;
	    case 's':		/* silent */
		to_stdout = 0;
		break;
	    case 'k':		/* backward compat */
		keep_alive = 1;
		break;
	    case 'r':		/* reload */
		reload = 1;
		break;
	    case 'p':		/* port number */
		sscanf(optarg, "%d", &port);
		if (port < 1)
		    port = CACHE_HTTP_PORT;	/* default */
		break;
	    case 'i':		/* IMS */
		ims = (time_t) atoi(optarg);
		break;
	    case 'm':
		method = xstrdup(optarg);
		break;
	    case 't':
		method = xstrdup("TRACE");
		max_forwards = atoi(optarg);
		break;
	    case 'g':
		ping = 1;
		pcount = atoi(optarg);
		to_stdout = 0;
		break;
	    case 'I':
		if ((ping_int = atoi(optarg) * 1000) <= 0)
		    usage(argv[0]);
		break;
	    case '?':		/* usage */
	    default:
		usage(argv[0]);
		break;
	    }
    }
    /* Build the HTTP request */
    if (strncmp(url, "mgr:", 4) == 0) {
	char *t = xstrdup(url + 4);
	snprintf(url, BUFSIZ, "cache_object://%s/%s", hostname, t);
	xfree(t);
    }
    snprintf(msg, BUFSIZ, "%s %s HTTP/1.0\r\n", method, url);
    if (reload) {
	snprintf(buf, BUFSIZ, "Pragma: no-cache\r\n");
	strcat(msg, buf);
    }
    if (opt_noaccept == 0) {
	snprintf(buf, BUFSIZ, "Accept: */*\r\n");
	strcat(msg, buf);
    }
    if (ims) {
	snprintf(buf, BUFSIZ, "If-Modified-Since: %s\r\n", mkrfc1123(ims));
	strcat(msg, buf);
    }
    if (max_forwards > -1) {
	snprintf(buf, BUFSIZ, "Max-Forwards: %d\r\n", max_forwards);
	strcat(msg, buf);
    }
    if (keep_alive) {
	if (port != 80)
	    snprintf(buf, BUFSIZ, "Proxy-Connection: Keep-Alive\r\n");
	else
	    snprintf(buf, BUFSIZ, "Connection: Keep-Alive\r\n");
	strcat(msg, buf);
    }
    snprintf(buf, BUFSIZ, "\r\n");
    strcat(msg, buf);

    if (ping) {
#if HAVE_SIGACTION
	struct sigaction sa, osa;
	if (sigaction(SIGINT, NULL, &osa) == 0 && osa.sa_handler == SIG_DFL) {
	    sa.sa_handler = catch;
	    sa.sa_flags = 0;
	    sigemptyset(&sa.sa_mask);
	    (void) sigaction(SIGINT, &sa, NULL);
	}
#else
	void (*osig) ();
	if ((osig = signal(SIGINT, catch)) != SIG_DFL)
	    (void) signal(SIGINT, osig);
#endif
    }
    loops = ping ? pcount : 1;
    for (i = 0; loops == 0 || i < loops; i++) {
	/* Connect to the server */
	if ((conn = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	    perror("client: socket");
	    exit(1);
	}
	if (client_comm_connect(conn, hostname, port, ping ? &tv1 : NULL) < 0) {
	    if (errno == 0) {
		fprintf(stderr, "client: ERROR: Cannot connect to %s:%d: Host unknown.\n", hostname, port);
	    } else {
		char tbuf[BUFSIZ];
		snprintf(tbuf, BUFSIZ, "client: ERROR: Cannot connect to %s:%d",
		    hostname, port);
		perror(tbuf);
	    }
	    exit(1);
	}
	/* Send the HTTP request */
	bytesWritten = write(conn, msg, strlen(msg));
	if (bytesWritten < 0) {
	    perror("client: ERROR: write");
	    exit(1);
	} else if (bytesWritten != strlen(msg)) {
	    fprintf(stderr, "client: ERROR: Cannot send request?: %s\n", msg);
	    exit(1);
	}
	/* Read the data */
	while ((len = read(conn, buf, sizeof(buf))) > 0) {
	    if (to_stdout)
		fwrite(buf, len, 1, stdout);
	}
	(void) close(conn);	/* done with socket */

	if (interrupted)
	    break;

	if (ping) {
	    struct tm *tmp;
	    time_t t2s;
	    long elapsed_msec;

	    (void) Now(&tv2);
	    elapsed_msec = tvSubMsec(tv1, tv2);
	    t2s = tv2.tv_sec;
	    tmp = localtime(&t2s);
	    fprintf(stderr, "%d-%02d-%02d %02d:%02d:%02d [%d]: %ld.%03ld secs\n",
		tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
		tmp->tm_hour, tmp->tm_min, tmp->tm_sec, i + 1,
		elapsed_msec / 1000, elapsed_msec % 1000);
	    if (i == 0 || elapsed_msec < ping_min)
		ping_min = elapsed_msec;
	    if (i == 0 || elapsed_msec > ping_max)
		ping_max = elapsed_msec;
	    ping_sum += elapsed_msec;
	    /* Delay until next "ping_int" boundary */
	    if ((loops == 0 || i + 1 < loops) && elapsed_msec < ping_int) {
		struct timeval tvs;
		long msec_left = ping_int - elapsed_msec;

		tvs.tv_sec = msec_left / 1000;
		tvs.tv_usec = (msec_left % 1000) * 1000;
		select(0, NULL, NULL, NULL, &tvs);
	    }
	}
    }

    if (ping && i) {
	ping_mean = ping_sum / i;
	fprintf(stderr, "%d requests, round-trip (secs) min/avg/max = "
	    "%ld.%03ld/%ld.%03ld/%ld.%03ld\n", i,
	    ping_min / 1000, ping_min % 1000, ping_mean / 1000, ping_mean % 1000,
	    ping_max / 1000, ping_max % 1000);
    }
    exit(0);
    /*NOTREACHED */
    return 0;
}

static int
client_comm_connect(int sock, char *dest_host, u_short dest_port, struct timeval *tvp)
{
    static const struct hostent *hp = NULL;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    if (hp == NULL) {
	to_addr.sin_family = AF_INET;

	if ((hp = gethostbyname(dest_host)) == 0) {
	    return (-1);
	}
	xmemcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
	to_addr.sin_port = htons(dest_port);
    }
    if (tvp)
	(void) Now(tvp);
    return connect(sock, (struct sockaddr *) &to_addr, sizeof(struct sockaddr_in));
}

static int
Now(struct timeval *tp)
{
#if GETTIMEOFDAY_NO_TZP
    return gettimeofday(tp);
#else
    return gettimeofday(tp, NULL);
#endif
}				/* ARGSUSED */

static void
catch(int sig)
{
    interrupted = 1;
    fprintf(stderr, "Interrupted.\n");
}
