
/*
 * $Id: dns.cc,v 1.66 1998/09/29 16:33:44 wessels Exp $
 *
 * DEBUG: section 34    Dnsserver interface
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

struct dnsQueueData {
    struct dnsQueueData *next;
    void *data;
};

static PF dnsShutdownRead;
static PF dnsFDClosed;
static dnsserver_t **dns_child_table = NULL;
static int NDnsServersRunning = 0;

static void
dnsFDClosed(int fd, void *data)
{
    dnsserver_t *dns = data;
    NDnsServersRunning--;
    if (shutting_down || reconfiguring)
	return;
    debug(34, 0) ("WARNING: DNSSERVER #%d (FD %d) exited\n",
	dns->id, fd);
    if (NDnsServersRunning < Config.dnsChildren / 2)
	fatal("Too few DNSSERVER processes are running");
}

dnsserver_t *
dnsGetFirstAvailable(void)
{
    int k;
    dnsserver_t *dns = NULL;
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	if (dns->flags.busy)
	    continue;
	if (dns->flags.closing)
	    continue;
	if (!dns->flags.alive)
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
    NDnsServersRunning = 0;
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
	    dns_child_table[k]->flags.alive = 0;
	    dns_child_table[k]->id = k + 1;
	    dns_child_table[k]->inpipe = -1;
	    dns_child_table[k]->outpipe = -1;
	} else {
	    debug(34, 4) ("dnsOpenServers: FD %d connected to %s #%d.\n",
		wfd, prg, k + 1);
	    dns_child_table[k]->flags.alive = 1;
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
	    comm_add_close_handler(dns_child_table[k]->inpipe, dnsFDClosed,
		dns_child_table[k]);
	    debug(34, 3) ("dnsOpenServers: DNSSERVER #%d started\n", k + 1);
	    NDnsServersAlloc++;
	    NDnsServersRunning++;
	}
    }
    if (NDnsServersAlloc == 0 && Config.dnsChildren > 0)
	fatal("Failed to start any dnsservers");
    if (NDnsServersRunning < Config.dnsChildren / 2)
	fatal("Too few DNSSERVER processes are running");
    cachemgrRegister("dns", "dnsserver child process information",
	dnsStats, 0, 1);
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
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "%7s\t%7s\t%11s\t%s\t%7s\t%7s\n",
	"#",
	"FD",
	"# Requests",
	"Flags",
	"Time",
	"Offset");
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	storeAppendPrintf(sentry, "%7d\t%7d\t%11d\t%c%c%c%c\t%7.3f\t%7d\n",
	    k + 1,
	    dns->inpipe,
	    DnsStats.hist[k],
	    dns->flags.alive ? 'A' : ' ',
	    dns->flags.busy ? 'B' : ' ',
	    dns->flags.closing ? 'C' : ' ',
	    dns->flags.shutdown ? 'S' : ' ',
	    0.001 * tvSubMsec(dns->dispatch_time, current_time),
	    (int) dns->offset);
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
}

void
dnsShutdownServers(void *notused)
{
    dnsserver_t *dns = NULL;
    int k;
    int na = 0;
    debug(34, 3) ("dnsShutdownServers:\n");
    for (k = 0; k < NDnsServersAlloc; k++) {
	dns = *(dns_child_table + k);
	if (!dns->flags.alive) {
	    debug(34, 3) ("dnsShutdownServers: #%d is NOT ALIVE.\n", dns->id);
	    continue;
	}
	if (dns->flags.busy) {
	    debug(34, 3) ("dnsShutdownServers: #%d is BUSY.\n", dns->id);
	    dns->flags.shutdown = 1;
	    na++;
	    continue;
	}
	if (dns->flags.closing) {
	    debug(34, 3) ("dnsShutdownServers: #%d is CLOSING.\n", dns->id);
	    continue;
	}
	dnsShutdownServer(dns);
    }
    /*
     * Here we pass in 'dns_child_table[0]' as callback data so that
     * if the dns_child_table[] array gets freed, the event will
     * never execute.
     */
    if (na)
	eventAdd("dnsShutdownServers",
	    dnsShutdownServers,
	    dns_child_table[0],
	    1.0,
	    1);
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
    dns->flags.closing = 1;
}

static void
dnsShutdownRead(int fd, void *data)
{
    dnsserver_t *dns = data;
    debug(14, dns->flags.closing ? 5 : 1)
	("FD %d: Connection from DNSSERVER #%d is closed, disabling\n",
	fd,
	dns->id);
    dns->flags.alive = 0;
    dns->flags.busy = 0;
    dns->flags.closing = 0;
    dns->flags.shutdown = 0;
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    cbdataUnlock(dns);
    comm_close(fd);
}

#ifdef SQUID_SNMP
/*
 * The function to return the DNS via SNMP
 */

variable_list *
snmp_netDnsFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;

    debug(49, 5) ("snmp_netDnsFn: Processing request:\n", Var->name[LEN_SQ_NET +
	    1]);
    snmpDebugOid(5, Var->name, Var->name_length);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(snint);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = SMI_COUNTER32;

    switch (Var->name[LEN_SQ_NET + 1]) {
    case DNS_REQ:
	*(Answer->val.integer) = DnsStats.requests;
	break;
    case DNS_REP:
	*(Answer->val.integer) = DnsStats.replies;
	break;
    case DNS_SERVERS:
	*(Answer->val.integer) = NDnsServersAlloc;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

#endif /*SQUID_SNMP */
