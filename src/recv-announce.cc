/*
 * $Id: recv-announce.cc,v 1.10 1996/09/20 06:29:04 wessels Exp $
 *
 * DEBUG: section 0     Announement Server
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

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>

#define RECV_BUF_SIZE 8192

extern void xmemcpy _PARAMS((void *from, void *to, int len));

/*
 * This program must be run from inetd.  First add something like this
 * to /etc/services:
 * 
 * cached_announce 3131/udp             # cache announcements
 * 
 * And then add something like this to /etc/inetd/conf:
 * 
 * cached_announce dgram udp       wait cached /tmp/recv-announce recv-announce /tmp/recv-announce.log
 * 
 * 
 * A single instance of this process will continue to handle incoming
 * requests.  If it dies, or is killed, inetd should restart it when the
 * next message arrives.
 * 
 */

/* 
 * usage: recv-announce logfile
 */

void
sig_handle(void)
{
    fflush(stdout);
    close(2);
    close(1);
    close(0);
    exit(0);
}


int
main(int argc, char *argv[])
{
    char buf[RECV_BUF_SIZE];
    struct sockaddr_in R;
    int len;
    struct hostent *hp = NULL;
    char logfile[BUFSIZ];
    char ip[4];

    for (len = 0; len < 32; len++) {
	signal(len, sig_handle);
    }


    if (argc > 1)
	strcpy(logfile, argv[1]);
    else
	strcpy(logfile, "/tmp/recv-announce.log");

    close(1);
    if (open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0660) < 0) {
	perror(logfile);
	exit(1);
    }
    close(2);
    dup(1);


    while (1) {
	memset(buf, '\0', RECV_BUF_SIZE);
	memset(&R, '\0', len = sizeof(R));

	if (recvfrom(0, buf, RECV_BUF_SIZE, 0, &R, &len) < 0) {
	    perror("recv");
	    exit(2);
	}
	xmemcpy(ip, &R.sin_addr.s_addr, 4);
	hp = gethostbyaddr(ip, 4, AF_INET);
	printf("==============================================================================\n");
	printf("Received from %s [%s]\n",
	    inet_ntoa(R.sin_addr),
	    (hp && hp->h_name) ? hp->h_name : "Unknown");
	fputs(buf, stdout);
	fflush(stdout);
    }
    return 0;
}
