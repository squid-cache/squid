/*
 * $Id: dns.cc,v 1.9 1996/09/16 21:11:06 wessels Exp $
 *
 * DEBUG: section 34    Dnsserver interface
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

#include "squid.h"

struct dnsQueueData {
    struct dnsQueueData *next;
    void *data;
};

static int dnsOpenServer __P((char *command));

static dnsserver_t **dns_child_table = NULL;
static int NDnsServersAlloc = 0;

char *dns_error_message = NULL;	/* possible error message */
struct _dnsStats DnsStats;

static int
dnsOpenServer(char *command)
{
    int pid;
    u_short port;
    struct sockaddr_in S;
    int cfd;
    int sfd;
    int len;
    LOCAL_ARRAY(char, buf, 128);

    cfd = comm_open(SOCK_STREAM,
	0,
	local_addr,
	0,
	COMM_NOCLOEXEC,
	"socket to dnsserver");
    if (cfd == COMM_ERROR) {
	debug(34, 0, "dnsOpenServer: Failed to create dnsserver\n");
	return -1;
    }
    len = sizeof(S);
    memset(&S, '\0', len);
    if (getsockname(cfd, (struct sockaddr *) &S, &len) < 0) {
	debug(34, 0, "dnsOpenServer: getsockname: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    port = ntohs(S.sin_port);
    debug(34, 4, "dnsOpenServer: bind to local host.\n");
    listen(cfd, 1);
    if ((pid = fork()) < 0) {
	debug(34, 0, "dnsOpenServer: fork: %s\n", xstrerror());
	comm_close(cfd);
	return -1;
    }
    if (pid > 0) {		/* parent */
	comm_close(cfd);	/* close shared socket with child */
	/* open new socket for parent process */
	sfd = comm_open(SOCK_STREAM,
		0,		/* protocol */
		local_addr,
		0,		/* port */
		0,		/* flags */
		NULL);	/* blocking! */
	if (sfd == COMM_ERROR)
	    return -1;
	if (comm_connect(sfd, localhost, port) == COMM_ERROR) {
	    comm_close(sfd);
	    return -1;
	}
	if (write(sfd, "$hello\n", 7) < 0) {
	    debug(34, 0, "dnsOpenServer: $hello write test failed\n");
	    comm_close(sfd);
	    return -1;
	}
	memset(buf, '\0', 128);
	if (read(sfd, buf, 128) < 0 || strcmp(buf, "$alive\n$end\n")) {
	    debug(34, 0, "dnsOpenServer: $hello read test failed\n");
	    comm_close(sfd);
	    return -1;
	}
	comm_set_fd_lifetime(sfd, -1);
	return sfd;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    dup2(fileno(debug_log), 2);
    dup2(cfd, 3);
    close(cfd);
    execlp(command, "(dnsserver)", "-t", NULL);
    debug(34, 0, "dnsOpenServer: %s: %s\n", command, xstrerror());
    _exit(1);
    return 0;
}

dnsserver_t *
dnsGetFirstAvailable()
{
    int k;
    dnsserver_t *dns = NULL;
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	if (!(dns->flags & DNS_FLAG_BUSY))
	    return dns;
    }
    return NULL;
}


void
dnsOpenServers()
{
    int N = Config.dnsChildren;
    char *prg = Config.Program.dnsserver;
    int k;
    int dnssocket;
    LOCAL_ARRAY(char, fd_note_buf, FD_ASCII_NOTE_SZ);

    /* free old structures if present */
    if (dns_child_table) {
	for (k = 0; k < NDnsServersAlloc; k++) {
	    safe_free(dns_child_table[k]->ip_inbuf);
	    safe_free(dns_child_table[k]);
	}
	safe_free(dns_child_table);
    }
    dns_child_table = xcalloc(N, sizeof(dnsserver_t *));
    debug(34, 1, "dnsOpenServers: Starting %d 'dns_server' processes\n", N);
    NDnsServersAlloc = 0;
    for (k = 0; k < N; k++) {
	dns_child_table[k] = xcalloc(1, sizeof(dnsserver_t));
	if ((dnssocket = dnsOpenServer(prg)) < 0) {
	    debug(34, 1, "dnsOpenServers: WARNING: Cannot run 'dnsserver' process.\n");
	    debug(34, 1, "              Fallling back to the blocking version.\n");
	    dns_child_table[k]->flags &= ~DNS_FLAG_ALIVE;
	} else {
	    debug(34, 4, "dnsOpenServers: FD %d connected to %s #%d.\n",
		dnssocket, prg, k + 1);
	    dns_child_table[k]->flags |= DNS_FLAG_ALIVE;
	    dns_child_table[k]->id = k + 1;
	    dns_child_table[k]->inpipe = dnssocket;
	    dns_child_table[k]->outpipe = dnssocket;
	    dns_child_table[k]->lastcall = squid_curtime;
	    dns_child_table[k]->size = DNS_INBUF_SZ - 1;
	    dns_child_table[k]->offset = 0;
	    dns_child_table[k]->ip_inbuf = xcalloc(DNS_INBUF_SZ, 1);

	    /* update fd_stat */

	    sprintf(fd_note_buf, "%s #%d", prg, dns_child_table[k]->id);
	    fd_note(dns_child_table[k]->inpipe, fd_note_buf);
	    commSetNonBlocking(dns_child_table[k]->inpipe);
	    debug(34, 3, "dnsOpenServers: 'dns_server' %d started\n", k);
	    NDnsServersAlloc++;
	}
    }
}


void
dnsStats(StoreEntry * sentry)
{
    int k;

    storeAppendPrintf(sentry, "{DNSServer Statistics:\n");
    storeAppendPrintf(sentry, "{dnsserver requests: %d}\n",
	DnsStats.requests);
    storeAppendPrintf(sentry, "{dnsserver replies: %d}\n",
	DnsStats.replies);
    storeAppendPrintf(sentry, "{number of dnsservers: %d}\n",
	NDnsServersAlloc);
    storeAppendPrintf(sentry, "{dnsservers use histogram:}\n");
    for (k = 0; k < NDnsServersAlloc; k++) {
	storeAppendPrintf(sentry, "{    dnsserver #%d: %d}\n",
	    k + 1,
	    DnsStats.hist[k]);
    }
    storeAppendPrintf(sentry, "}\n\n");
    storeAppendPrintf(sentry, close_bracket);
}

void
dnsShutdownServers()
{
    dnsserver_t *dnsData = NULL;
    int k;
    static char *shutdown = "$shutdown\n";

    debug(34, 3, "dnsShutdownServers:\n");

    k = ipcacheQueueDrain();
    if (fqdncacheQueueDrain() || k)
	return;
    for (k = 0; k < NDnsServersAlloc; k++) {
	dnsData = *(dns_child_table + k);
	if (!(dnsData->flags & DNS_FLAG_ALIVE)) {
	    debug(34, 3, "dnsShutdownServers: #%d is NOT ALIVE.\n", dnsData->id);
	    continue;
	}
	if (dnsData->flags & DNS_FLAG_BUSY) {
	    debug(34, 3, "dnsShutdownServers: #%d is BUSY.\n", dnsData->id);
	    continue;
	}
	if (dnsData->flags & DNS_FLAG_CLOSING) {
	    debug(34, 3, "dnsShutdownServers: #%d is CLOSING.\n", dnsData->id);
	    continue;
	}
	debug(34, 3, "dnsShutdownServers: sending '$shutdown' to dnsserver #%d\n", dnsData->id);
	debug(34, 3, "dnsShutdownServers: --> FD %d\n", dnsData->outpipe);
	comm_write(dnsData->outpipe,
	    xstrdup(shutdown),
	    strlen(shutdown),
	    0,			/* timeout */
	    NULL,		/* Handler */
	    NULL,		/* Handler-data */
	    xfree);
	dnsData->flags |= DNS_FLAG_CLOSING;
    }
}
