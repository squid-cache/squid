

/*
 * $Id: client.cc,v 1.29 1997/08/25 23:45:24 wessels Exp $
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
static int client_comm_connect _PARAMS((int sock, char *dest_host, u_short dest_port));
static void usage _PARAMS((const char *progname));

static void
usage(const char *progname)
{
    fprintf(stderr,
	"Usage: %s [-ars] [-i IMS] [-h host] [-p port] [-m method] [-t count] url\n"
	"Options:\n"
	"    -a         Do NOT include Accept: header.\n"
	"    -r         Force cache to reload URL.\n"
	"    -s         Silent.  Do not print data to stdout.\n"
	"    -i IMS     If-Modified-Since time (in Epoch seconds).\n"
	"    -h host    Retrieve URL from cache on hostname.  Default is localhost.\n"
	"    -p port    Port number of cache.  Default is %d.\n"
	"    -m method  Request method, default is GET.\n"
	"    -t count   Trace count cache-hops\n",
	progname, CACHE_HTTP_PORT);
    exit(1);
}

int
main(int argc, char *argv[])
{
    int conn, c, len, bytesWritten;
    int port, to_stdout, reload;
    int keep_alive = 0;
    int opt_noaccept = 0;
    char url[BUFSIZ], msg[BUFSIZ], buf[BUFSIZ], hostname[BUFSIZ];
    const char *method = "GET";
    extern char *optarg;
    time_t ims = 0;
    int max_forwards = -1;

    /* set the defaults */
    strcpy(hostname, "localhost");
    port = CACHE_HTTP_PORT;
    to_stdout = 1;
    reload = 0;

    if (argc < 2) {
	usage(argv[0]);		/* need URL */
    } else if (argc >= 2) {
	strcpy(url, argv[argc - 1]);
	if (url[0] == '-')
	    usage(argv[0]);
	while ((c = getopt(argc, argv, "ah:i:km:p:rst:?")) != -1)
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
	    case '?':		/* usage */
	    default:
		usage(argv[0]);
		break;
	    }
    }
    /* Connect to the server */
    if ((conn = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	perror("client: socket");
	exit(1);
    }
    if (client_comm_connect(conn, hostname, port) < 0) {
	if (errno == 0) {
	    fprintf(stderr, "client: ERROR: Cannot connect to %s:%d: Host unknown.\n", hostname, port);
	} else {
	    char tbuf[BUFSIZ];
	    sprintf(tbuf, "client: ERROR: Cannot connect to %s:%d",
		hostname, port);
	    perror(tbuf);
	}
	exit(1);
    }
    /* Build the HTTP request */
    sprintf(msg, "%s %s HTTP/1.0\r\n", method, url);
    if (reload) {
	sprintf(buf, "Pragma: no-cache\r\n");
	strcat(msg, buf);
    }
    if (opt_noaccept == 0) {
	sprintf(buf, "Accept: */*\r\n");
	strcat(msg, buf);
    }
    if (ims) {
	sprintf(buf, "If-Modified-Since: %s\r\n", mkrfc1123(ims));
	strcat(msg, buf);
    }
    if (max_forwards > -1) {
	sprintf(buf, "Max-Forwards: %d\r\n", max_forwards);
	strcat(msg, buf);
    }
    if (keep_alive) {
	sprintf(buf, "Proxy-Connection: Keep-Alive\r\n");
	strcat(msg, buf);
    }
    sprintf(buf, "\r\n");
    strcat(msg, buf);

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
    (void) close(conn);		/* done with socket */
    exit(0);
    /*NOTREACHED */
    return 0;
}

static int
client_comm_connect(int sock, char *dest_host, u_short dest_port)
{
    const struct hostent *hp;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = gethostbyname(dest_host)) == 0) {
	return (-1);
    }
    xmemcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
    to_addr.sin_port = htons(dest_port);
    return connect(sock, (struct sockaddr *) &to_addr, sizeof(struct sockaddr_in));
}
