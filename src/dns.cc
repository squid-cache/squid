
/*
 * $Id: dns.cc,v 1.56 1998/02/19 23:09:50 wessels Exp $
 *
 * DEBUG: section 34    Dnsserver interface
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

struct dnsQueueData {
    struct dnsQueueData *next;
    void *data;
};

static PF dnsShutdownRead;
static dnsserver_t **dns_child_table = NULL;

dnsserver_t *
dnsGetFirstAvailable(void)
{
    int k;
    dnsserver_t *dns = NULL;
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	if (EBIT_TEST(dns->flags, HELPER_BUSY))
	    continue;
	if (EBIT_TEST(dns->flags, HELPER_CLOSING))
	    continue;
	if (!EBIT_TEST(dns->flags, HELPER_ALIVE))
	    continue;
	return dns;
    }
    return NULL;
}


void
dnsFreeMemory(void)
{
    int k;
    /* free old structures if present */
    if (dns_child_table) {
	for (k = 0; k < NDnsServersAlloc; k++)
	    cbdataFree(dns_child_table[k]);
	safe_free(dns_child_table);
    }
}

void
dnsOpenServers(void)
{
    int N = Config.dnsChildren;
    char *prg = Config.Program.dnsserver;
    int k;
    int x;
    int rfd;
    int wfd;
    LOCAL_ARRAY(char, fd_note_buf, FD_DESC_SZ);
    char *s;
    char *args[64];
    int nargs = 0;
    wordlist *w;

    dnsFreeMemory();
    dns_child_table = xcalloc(N, sizeof(dnsserver_t *));
    NDnsServersAlloc = 0;
    args[nargs++] = "(dnsserver)";
    if (Config.onoff.res_defnames)
	args[nargs++] = "-D";
    if (Config.dns_nameservers != NULL) {
	args[nargs++] = "-s";
	for (w = Config.dns_nameservers; w != NULL; w = w->next) {
	    if (nargs > 60)
		break;
	    args[nargs++] = w->key;
	}
    }
    args[nargs++] = NULL;
    for (k = 0; k < N; k++) {
	dns_child_table[k] = xcalloc(1, sizeof(dnsserver_t));
	cbdataAdd(dns_child_table[k], MEM_NONE);
	x = ipcCreate(IPC_TCP_SOCKET,
	    prg,
	    args,
	    "dnsserver",
	    &rfd,
	    &wfd);
	if (x < 0) {
	    debug(34, 1) ("dnsOpenServers: WARNING: Failed to start 'dnsserver' #%d.\n", k + 1);
	    EBIT_CLR(dns_child_table[k]->flags, HELPER_ALIVE);
	    dns_child_table[k]->id = k + 1;
	    dns_child_table[k]->inpipe = -1;
	    dns_child_table[k]->outpipe = -1;
	} else {
	    debug(34, 4) ("dnsOpenServers: FD %d connected to %s #%d.\n",
		wfd, prg, k + 1);
	    EBIT_SET(dns_child_table[k]->flags, HELPER_ALIVE);
	    dns_child_table[k]->id = k + 1;
	    dns_child_table[k]->inpipe = rfd;
	    dns_child_table[k]->outpipe = wfd;
	    dns_child_table[k]->answer = squid_curtime;
	    dns_child_table[k]->dispatch_time = current_time;
	    dns_child_table[k]->size = DNS_INBUF_SZ - 1;
	    dns_child_table[k]->offset = 0;
	    if ((s = strrchr(prg, '/')))
		s++;
	    else
		s = prg;
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", s, dns_child_table[k]->id);
	    fd_note(dns_child_table[k]->inpipe, fd_note_buf);
	    commSetNonBlocking(dns_child_table[k]->inpipe);
	    debug(34, 3) ("dnsOpenServers: 'dns_server' %d started\n", k + 1);
	    NDnsServersAlloc++;
	}
    }
    if (NDnsServersAlloc == 0 && Config.dnsChildren > 0)
	fatal("Failed to start any dnsservers");
    cachemgrRegister("dns", "dnsserver child process information",
	dnsStats, 0);
    debug(34, 1) ("Started %d 'dnsserver' processes\n", NDnsServersAlloc);
}


void
dnsStats(StoreEntry * sentry)
{
    int k;
    dnsserver_t *dns = NULL;
    storeAppendPrintf(sentry, "DNSServer Statistics:\n");
    storeAppendPrintf(sentry, "dnsserver requests: %d\n",
	DnsStats.requests);
    storeAppendPrintf(sentry, "dnsserver replies: %d\n",
	DnsStats.replies);
    storeAppendPrintf(sentry, "number of dnsservers: %d\n",
	NDnsServersAlloc);
    storeAppendPrintf(sentry, "dnsservers use histogram:\n");
    for (k = 0; k < NDnsServersAlloc; k++) {
	storeAppendPrintf(sentry, "    dnsserver #%d: %d\n",
	    k + 1,
	    DnsStats.hist[k]);
    }
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "dnsservers status:\n");
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	storeAppendPrintf(sentry, "dnsserver #%d:\n", k + 1);
	storeAppendPrintf(sentry, "    Flags: %c%c%c%c\n",
	    EBIT_TEST(dns->flags, HELPER_ALIVE) ? 'A' : ' ',
	    EBIT_TEST(dns->flags, HELPER_BUSY) ? 'B' : ' ',
	    EBIT_TEST(dns->flags, HELPER_CLOSING) ? 'C' : ' ',
	    EBIT_TEST(dns->flags, HELPER_SHUTDOWN) ? 'S' : ' ');
	storeAppendPrintf(sentry, "    FDs (in/out): %d/%d\n",
	    dns->inpipe, dns->outpipe);
	storeAppendPrintf(sentry, "    Alive since: %s\n",
	    mkrfc1123(dns->answer));
	storeAppendPrintf(sentry, "    Last Dispatched: %0.3f seconds ago\n",
	    0.001 * tvSubMsec(dns->dispatch_time, current_time));
	storeAppendPrintf(sentry, "    Read Buffer Size: %d bytes\n",
	    dns->size);
	storeAppendPrintf(sentry, "    Read Offset: %d bytes\n",
	    dns->offset);
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
}

void
dnsShutdownServers(void)
{
    dnsserver_t *dns = NULL;
    int k;
    debug(34, 3) ("dnsShutdownServers:\n");
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	if (!EBIT_TEST(dns->flags, HELPER_ALIVE)) {
	    debug(34, 3) ("dnsShutdownServers: #%d is NOT ALIVE.\n", dns->id);
	    continue;
	}
	if (EBIT_TEST(dns->flags, HELPER_BUSY)) {
	    debug(34, 3) ("dnsShutdownServers: #%d is BUSY.\n", dns->id);
	    EBIT_SET(dns->flags, HELPER_SHUTDOWN);
	    continue;
	}
	if (EBIT_TEST(dns->flags, HELPER_CLOSING)) {
	    debug(34, 3) ("dnsShutdownServers: #%d is CLOSING.\n", dns->id);
	    continue;
	}
	dnsShutdownServer(dns);
    }
}

void
dnsShutdownServer(dnsserver_t * dns)
{
    static char *shutdown_cmd = "$shutdown\n";
    debug(34, 3) ("dnsShutdownServer: sending '$shutdown' to dnsserver #%d\n",
	dns->id);
    debug(34, 3) ("dnsShutdownServer: --> FD %d\n", dns->outpipe);
    cbdataLock(dns);
    comm_write(dns->outpipe,
	xstrdup(shutdown_cmd),
	strlen(shutdown_cmd),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
    commSetSelect(dns->inpipe,
	COMM_SELECT_READ,
	dnsShutdownRead,
	dns,
	0);
    EBIT_SET(dns->flags, HELPER_CLOSING);
}

static void
dnsShutdownRead(int fd, void *data)
{
    dnsserver_t *dns = data;
    debug(14, EBIT_TEST(dns->flags, HELPER_CLOSING) ? 5 : 1)
	("FD %d: Connection from DNSSERVER #%d is closed, disabling\n",
	fd,
	dns->id);
    dns->flags = 0;
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    cbdataUnlock(dns);
    comm_close(fd);
}
