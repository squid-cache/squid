
/*
 * $Id: dns_internal.cc,v 1.8 1999/04/19 03:31:30 wessels Exp $
 *
 * DEBUG: section 78    DNS lookups; interacts with lib/rfc1035.c
 * AUTHOR: Duane Wessels
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

#ifndef _PATH_RESOLV_CONF
#define _PATH_RESOLV_CONF "/etc/resolv.conf"
#endif
#ifndef DOMAIN_PORT
#define DOMAIN_PORT 53
#endif

#define IDNS_MAX_TRIES 20

typedef struct _ns ns;
struct _ns {
    struct sockaddr_in S;
    int nqueries;
    int nreplies;
};
static ns *nameservers = NULL;
static int nns = 0;
static int nns_alloc = 0;
static dlink_list lru_list;
static int event_queued = 0;

static OBJH idnsStats;
static void idnsAddNameserver(const char *buf);
static void idnsFreeNameservers(void);
static void idnsParseResolvConf(void);
static void idnsSendQuery(idns_query * q);
static int idnsFromKnownNameserver(struct sockaddr_in *from);
static idns_query *idnsFindQuery(unsigned short id);
static void idnsGrokReply(const char *buf, size_t sz);
static PF idnsRead;
static EVH idnsCheckQueue;

static void
idnsAddNameserver(const char *buf)
{
    if (nns == nns_alloc) {
	int oldalloc = nns_alloc;
	ns *oldptr = nameservers;
	if (nns_alloc == 0)
	    nns_alloc = 2;
	else
	    nns_alloc <<= 1;
	nameservers = xcalloc(nns_alloc, sizeof(*nameservers));
	if (oldptr && oldalloc)
	    xmemcpy(nameservers, oldptr, oldalloc * sizeof(*nameservers));
	if (oldptr)
	    safe_free(oldptr);
    }
    assert(nns < nns_alloc);
    nameservers[nns].S.sin_family = AF_INET;
    nameservers[nns].S.sin_port = htons(DOMAIN_PORT);
    nameservers[nns].S.sin_addr.s_addr = inet_addr(buf);
    debug(78, 1) ("idnsAddNameserver: Added nameserver #%d: %s\n",
	nns, inet_ntoa(nameservers[nns].S.sin_addr));
    nns++;
}

static void
idnsFreeNameservers(void)
{
    safe_free(nameservers);
    nns = nns_alloc = 0;
}

static void
idnsParseResolvConf(void)
{
    FILE *fp;
    char buf[512];
    char *t;
    fp = fopen(_PATH_RESOLV_CONF, "r");
    if (fp == NULL) {
	debug(78, 1) ("%s: %s\n", _PATH_RESOLV_CONF, xstrerror());
	return;
    }
    idnsFreeNameservers();
    while (fgets(buf, 512, fp)) {
	t = strtok(buf, w_space);
	if (strcasecmp(t, "nameserver"))
	    continue;
	t = strtok(NULL, w_space);
	if (t == NULL)
	    continue;;
	debug(78, 1) ("idnsParseResolvConf: nameserver %s\n", t);
	idnsAddNameserver(t);
    }
    fclose(fp);
}

static void
idnsStats(StoreEntry * sentry)
{
    dlink_node *n;
    idns_query *q;
    int i;
    storeAppendPrintf(sentry, "Internal DNS Statistics:\n");
    storeAppendPrintf(sentry, "\nThe Queue:\n");
    storeAppendPrintf(sentry, "                       DELAY SINCE\n");
    storeAppendPrintf(sentry, "  ID   SIZE SENDS FIRST SEND LAST SEND\n");
    storeAppendPrintf(sentry, "------ ---- ----- ---------- ---------\n");
    for (n = lru_list.head; n; n = n->next) {
	q = n->data;
	storeAppendPrintf(sentry, "%#06x %4d %5d %10.3f %9.3f\n",
	    (int) q->id, q->sz, q->nsends,
	    tvSubDsec(q->start_t, current_time),
	    tvSubDsec(q->sent_t, current_time));
    }
    storeAppendPrintf(sentry, "\nNameservers:\n");
    storeAppendPrintf(sentry, "IP ADDRESS      # QUERIES # REPLIES\n");
    storeAppendPrintf(sentry, "--------------- --------- ---------\n");
    for (i = 0; i < nns; i++) {
	storeAppendPrintf(sentry, "%-15s %9d %9d\n",
	    inet_ntoa(nameservers[i].S.sin_addr),
	    nameservers[i].nqueries,
	    nameservers[i].nreplies);
    }
}

static void
idnsSendQuery(idns_query * q)
{
    int x;
    int ns;
    if (DnsSocket < 0) {
	debug(78, 1) ("idnsSendQuery: Can't send query, no DNS socket!\n");
	return;
    }
    /* XXX Select nameserver */
    assert(nns > 0);
    assert(q->lru.next == NULL);
    assert(q->lru.prev == NULL);
    ns = q->nsends % nns;
    x = comm_udp_sendto(DnsSocket,
	&nameservers[ns].S,
	sizeof(nameservers[ns].S),
	q->buf,
	q->sz);
    if (x < 0) {
	debug(50, 1) ("idnsSendQuery: FD %d: sendto: %s\n",
	    DnsSocket, xstrerror());
    } else {
	fd_bytes(DnsSocket, x, FD_WRITE);
    }
    q->nsends++;
    q->sent_t = current_time;
    nameservers[ns].nqueries++;
    dlinkAdd(q, &q->lru, &lru_list);
    if (!event_queued) {
	eventAdd("idnsCheckQueue", idnsCheckQueue, NULL, 1.0, 1);
	event_queued = 1;
    }
}

static int
idnsFromKnownNameserver(struct sockaddr_in *from)
{
    int i;
    for (i = 0; i < nns; i++) {
	if (nameservers[i].S.sin_addr.s_addr != from->sin_addr.s_addr)
	    continue;
	if (nameservers[i].S.sin_port != from->sin_port)
	    continue;
	return i;
    }
    return -1;
}

static idns_query *
idnsFindQuery(unsigned short id)
{
    dlink_node *n;
    idns_query *q;
    for (n = lru_list.tail; n; n = n->prev) {
	q = n->data;
	if (q->id == id)
	    return q;
    }
    return NULL;
}

static void
idnsGrokReply(const char *buf, size_t sz)
{
    int n;
    int valid;
    rfc1035_rr *answers = NULL;
    unsigned short rid = 0xFFFF;
    idns_query *q;
    n = rfc1035AnswersUnpack(buf,
	sz,
	&answers,
	&rid);
    debug(78, 3) ("idnsGrokReply: ID %#hx, %d answers\n", rid, n);
    if (rid == 0xFFFF) {
	debug(78, 1) ("idnsGrokReply: Unknown error\n");
	/* XXX leak answers? */
	return;
    }
    q = idnsFindQuery(rid);
    if (q == NULL) {
	debug(78, 1) ("idnsGrokReply: Didn't find query!\n");
	rfc1035RRDestroy(answers, n);
	return;
    }
    dlinkDelete(&q->lru, &lru_list);
    if (n < 0)
	debug(78, 1) ("idnsGrokReply: error %d\n", rfc1035_errno);
    valid = cbdataValid(q->callback_data);
    cbdataUnlock(q->callback_data);
    if (valid)
	q->callback(q->callback_data, answers, n);
    rfc1035RRDestroy(answers, n);
    memFree(q, MEM_IDNS_QUERY);
}

static void
idnsRead(int fd, void *data)
{
    int *N = data;
    ssize_t len;
    struct sockaddr_in from;
    socklen_t from_len;
    int max = 10;
    static char rbuf[512];
    int ns;
    commSetSelect(fd, COMM_SELECT_READ, idnsRead, NULL, 0);
    while (max--) {
	from_len = sizeof(from);
	memset(&from, '\0', from_len);
	Counter.syscalls.sock.recvfroms++;
	len = recvfrom(fd, rbuf, 512, 0, (struct sockaddr *) &from, &from_len);
	if (len == 0)
	    break;
	if (len < 0) {
	    if (ignoreErrno(errno))
		break;
#ifdef _SQUID_LINUX_
	    /* Some Linux systems seem to set the FD for reading and then
	     * return ECONNREFUSED when sendto() fails and generates an ICMP
	     * port unreachable message. */
	    /* or maybe an EHOSTUNREACH "No route to host" message */
	    if (errno != ECONNREFUSED && errno != EHOSTUNREACH)
#endif
		debug(50, 1) ("idnsRead: FD %d recvfrom: %s\n",
		    fd, xstrerror());
	    break;
	}
	fd_bytes(DnsSocket, len, FD_READ);
	(*N)++;
	debug(78, 3) ("idnsRead: FD %d: received %d bytes from %s.\n",
	    fd,
	    len,
	    inet_ntoa(from.sin_addr));
	ns = idnsFromKnownNameserver(&from);
	if (ns < 0) {
	    debug(78, 1) ("idnsRead: Reply from unknown nameserver [%s]\n",
		inet_ntoa(from.sin_addr));
	    continue;
	}
	nameservers[ns].nreplies++;
	idnsGrokReply(rbuf, len);
    }
}

static void
idnsCheckQueue(void *unused)
{
    dlink_node *n;
    idns_query *q;
    event_queued = 0;
    for (n = lru_list.tail; n; n = n->prev) {
	q = n->data;
	if (tvSubDsec(q->sent_t, current_time) < 5.0)
	    break;
	debug(78, 1) ("idnsCheckQueue: ID %#04x timeout\n",
	    q->id);
	dlinkDelete(&q->lru, &lru_list);
	if (q->nsends < IDNS_MAX_TRIES) {
	    idnsSendQuery(q);
	} else {
	    int v = cbdataValid(q->callback_data);
	    debug(78, 1) ("idnsCheckQueue: ID %x: giving up after %d tries\n",
		(int) q->id, q->nsends);
	    cbdataUnlock(q->callback_data);
	    if (v)
		q->callback(q->callback_data, NULL, 0);
	    memFree(q, MEM_IDNS_QUERY);
	}
    }
}

/* ====================================================================== */

void
idnsInit(void)
{
    static int init = 0;
    if (DnsSocket < 0) {
	DnsSocket = comm_open(SOCK_DGRAM,
	    0,
	    Config.Addrs.udp_outgoing,
	    0,
	    COMM_NONBLOCKING,
	    "DNS Socket");
	if (DnsSocket < 0)
	    fatal("Could not create a DNS socket");
	debug(78, 1) ("DNS Socket created on FD %d\n", DnsSocket);
	commSetSelect(DnsSocket, COMM_SELECT_READ, idnsRead, NULL, 0);
    }
    if (nns == 0)
	idnsParseResolvConf();
    if (!init) {
	cachemgrRegister("idns",
	    "Internal DNS Statistics",
	    idnsStats, 0, 1);
    }
    init++;
}

void
idnsShutdown(void)
{
    if (DnsSocket < 0)
	return;
    comm_close(DnsSocket);
    DnsSocket = -1;
}

void
idnsALookup(const char *name, IDNSCB * callback, void *data)
{
    idns_query *q = memAllocate(MEM_IDNS_QUERY);
    q->sz = sizeof(q->buf);
    q->id = rfc1035BuildAQuery(name, q->buf, &q->sz);
    debug(78, 3) ("idnsALookup: buf is %d bytes for %s, id = %#hx\n",
	(int) q->sz, name, q->id);
    q->callback = callback;
    q->callback_data = data;
    cbdataLock(q->callback_data);
    q->start_t = current_time;
    idnsSendQuery(q);
}

void
idnsPTRLookup(const struct in_addr addr, IDNSCB * callback, void *data)
{
    idns_query *q = memAllocate(MEM_IDNS_QUERY);
    q->sz = sizeof(q->buf);
    q->id = rfc1035BuildPTRQuery(addr, q->buf, &q->sz);
    debug(78, 3) ("idnsPTRLookup: buf is %d bytes for %s, id = %#hx\n",
	(int) q->sz, inet_ntoa(addr), q->id);
    q->callback = callback;
    q->callback_data = data;
    cbdataLock(q->callback_data);
    q->start_t = current_time;
    idnsSendQuery(q);
}
