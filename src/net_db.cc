
/*
 * $Id: net_db.cc,v 1.73 1998/03/03 17:10:57 wessels Exp $
 *
 * DEBUG: section 37    Network Measurement Database
 * AUTHOR: Duane Wessels
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

#include "squid.h"

#if USE_ICMP

static hash_table *addr_table = NULL;
static hash_table *host_table = NULL;

static struct in_addr networkFromInaddr(struct in_addr a);
static void netdbRelease(netdbEntry * n);
static void netdbHashInsert(netdbEntry * n, struct in_addr addr);
static void netdbHashDelete(const char *key);
static void netdbHostInsert(netdbEntry * n, const char *hostname);
static void netdbHostDelete(const net_db_name * x);
static void netdbPurgeLRU(void);
static netdbEntry *netdbLookupHost(const char *key);
static net_db_peer *netdbPeerByName(const netdbEntry * n, const char *);
static net_db_peer *netdbPeerAdd(netdbEntry * n, peer * e);
static char *netdbPeerName(const char *name);
static IPH netdbSendPing;
static QS sortPeerByRtt;
static QS sortByRtt;
static QS netdbLRU;

/* We have to keep a local list of peer names.  The Peers structure
 * gets freed during a reconfigure.  We want this database to
 * remain persisitent, so _net_db_peer->peername points into this
 * linked list */
static wordlist *peer_names = NULL;
static wordlist **peer_names_tail = &peer_names;

static void
netdbHashInsert(netdbEntry * n, struct in_addr addr)
{
    xstrncpy(n->network, inet_ntoa(networkFromInaddr(addr)), 16);
    n->key = n->network;
    assert(hash_lookup(addr_table, n->network) == NULL);
    hash_join(addr_table, (hash_link *) n);
}

static void
netdbHashDelete(const char *key)
{
    hash_link *hptr = hash_lookup(addr_table, key);
    if (hptr == NULL) {
	debug_trap("netdbHashDelete: key not found");
	return;
    }
    hash_remove_link(addr_table, hptr);
}

static void
netdbHostInsert(netdbEntry * n, const char *hostname)
{
    net_db_name *x = memAllocate(MEM_NET_DB_NAME);
    x->name = xstrdup(hostname);
    x->next = n->hosts;
    n->hosts = x;
    x->net_db_entry = n;
    assert(hash_lookup(host_table, hostname) == NULL);
    hash_join(host_table, (hash_link *) x);
    n->link_count++;
}

static void
netdbHostDelete(const net_db_name * x)
{
    netdbEntry *n;
    net_db_name **X;
    assert(x != NULL);
    assert(x->net_db_entry != NULL);
    n = x->net_db_entry;
    n->link_count--;
    for (X = &n->hosts; *X; X = &(*X)->next) {
	if (*X == x) {
	    *X = x->next;
	    break;
	}
    }
    hash_remove_link(host_table, (hash_link *) x);
    xfree(x->name);
    memFree(MEM_NET_DB_NAME, (void *) x);
}

static netdbEntry *
netdbLookupHost(const char *key)
{
    net_db_name *x = (net_db_name *) hash_lookup(host_table, key);
    return x ? x->net_db_entry : NULL;
}

static void
netdbRelease(netdbEntry * n)
{
    net_db_name *x;
    net_db_name *next;
    for (x = n->hosts; x; x = next) {
	next = x->next;
	netdbHostDelete(x);
    }
    n->hosts = NULL;
    safe_free(n->peers);
    meta_data.netdb_peers -= n->n_peers_alloc;
    n->peers = NULL;
    n->n_peers = 0;
    n->n_peers_alloc = 0;
    if (n->link_count == 0) {
	netdbHashDelete(n->network);
	memFree(MEM_NETDBENTRY, n);
    }
}

static int
netdbLRU(const void *A, const void *B)
{
    const netdbEntry *const *n1 = A;
    const netdbEntry *const *n2 = B;
    if ((*n1)->last_use_time > (*n2)->last_use_time)
	return (1);
    if ((*n1)->last_use_time < (*n2)->last_use_time)
	return (-1);
    return (0);
}

static void
netdbPurgeLRU(void)
{
    netdbEntry *n;
    netdbEntry **list;
    int k = 0;
    int list_count = 0;
    int removed = 0;
    list = xcalloc(memInUse(MEM_NETDBENTRY), sizeof(netdbEntry *));
    n = (netdbEntry *) hash_first(addr_table);
    while (n != NULL) {
	assert(list_count < memInUse(MEM_NETDBENTRY));
	*(list + list_count) = n;
	list_count++;
	n = (netdbEntry *) hash_next(addr_table);
    }
    qsort((char *) list,
	list_count,
	sizeof(netdbEntry *),
	netdbLRU);
    for (k = 0; k < list_count; k++) {
	if (memInUse(MEM_NETDBENTRY) < Config.Netdb.low)
	    break;
	netdbRelease(*(list + k));
	removed++;
    }
    xfree(list);
}

static netdbEntry *
netdbLookupAddr(struct in_addr addr)
{
    netdbEntry *n;
    char *key = inet_ntoa(networkFromInaddr(addr));
    n = (netdbEntry *) hash_lookup(addr_table, key);
    return n;
}

static netdbEntry *
netdbAdd(struct in_addr addr)
{
    netdbEntry *n;
    if (memInUse(MEM_NETDBENTRY) > Config.Netdb.high)
	netdbPurgeLRU();
    if ((n = netdbLookupAddr(addr)) == NULL) {
	n = memAllocate(MEM_NETDBENTRY);
	netdbHashInsert(n, addr);
    }
    return n;
}

static void
netdbSendPing(const ipcache_addrs * ia, void *data)
{
    struct in_addr addr;
    char *hostname = data;
    netdbEntry *n;
    netdbEntry *na;
    net_db_name *x;
    net_db_name **X;
    cbdataUnlock(hostname);
    if (ia == NULL) {
	cbdataFree(hostname);
	return;
    }
    addr = ia->in_addrs[ia->cur];
    if ((n = netdbLookupHost(hostname)) == NULL) {
	n = netdbAdd(addr);
	netdbHostInsert(n, hostname);
    } else if ((na = netdbLookupAddr(addr)) != n) {
	/*
	 *hostname moved from 'network n' to 'network na'!
	 */
	if (na == NULL)
	    na = netdbAdd(addr);
	debug(37, 3) ("netdbSendPing: %s moved from %s to %s\n",
	    hostname, n->network, na->network);
	x = (net_db_name *) hash_lookup(host_table, hostname);
	if (x == NULL) {
	    debug(37, 1) ("netdbSendPing: net_db_name list bug: %s not found", hostname);
	    cbdataFree(hostname);
	    return;
	}
	/* remove net_db_name from 'network n' linked list */
	for (X = &n->hosts; *X; X = &(*X)->next) {
	    if (*X == x) {
		*X = x->next;
		break;
	    }
	}
	n->link_count--;
	/* point to 'network na' from host entry */
	x->net_db_entry = na;
	/* link net_db_name to 'network na' */
	x->next = na->hosts;
	na->hosts = x;
	na->link_count++;
	n = na;
    }
    debug(37, 3) ("netdbSendPing: pinging %s\n", hostname);
    icmpDomainPing(addr, hostname);
    n->pings_sent++;
    n->next_ping_time = squid_curtime + Config.Netdb.period;
    n->last_use_time = squid_curtime;
    cbdataFree(hostname);
}

static struct in_addr
networkFromInaddr(struct in_addr a)
{
    struct in_addr b;
    b.s_addr = ntohl(a.s_addr);
#if USE_CLASSFUL
    if (IN_CLASSC(b.s_addr))
	b.s_addr &= IN_CLASSC_NET;
    else if (IN_CLASSB(b.s_addr))
	b.s_addr &= IN_CLASSB_NET;
    else if (IN_CLASSA(b.s_addr))
	b.s_addr &= IN_CLASSA_NET;
#else
    /* use /24 for everything */
    b.s_addr &= IN_CLASSC_NET;
#endif
    b.s_addr = htonl(b.s_addr);
    return b;
}

static int
sortByRtt(const void *A, const void *B)
{
    const netdbEntry *const *n1 = A;
    const netdbEntry *const *n2 = B;
    if ((*n1)->rtt > (*n2)->rtt)
	return 1;
    else if ((*n1)->rtt < (*n2)->rtt)
	return -1;
    else
	return 0;
}

static net_db_peer *
netdbPeerByName(const netdbEntry * n, const char *peername)
{
    int i;
    net_db_peer *p = n->peers;
    for (i = 0; i < n->n_peers; i++, p++) {
	if (!strcmp(p->peername, peername))
	    return p;
    }
    return NULL;
}

static net_db_peer *
netdbPeerAdd(netdbEntry * n, peer * e)
{
    net_db_peer *p;
    net_db_peer *o;
    int osize;
    int i;
    if (n->n_peers == n->n_peers_alloc) {
	o = n->peers;
	osize = n->n_peers_alloc;
	if (n->n_peers_alloc == 0)
	    n->n_peers_alloc = 2;
	else
	    n->n_peers_alloc <<= 1;
	debug(37, 3) ("netdbPeerAdd: Growing peer list for '%s' to %d\n",
	    n->network, n->n_peers_alloc);
	n->peers = xcalloc(n->n_peers_alloc, sizeof(net_db_peer));
	meta_data.netdb_peers += n->n_peers_alloc;
	for (i = 0; i < osize; i++)
	    *(n->peers + i) = *(o + i);
	if (osize) {
	    safe_free(o);
	    meta_data.netdb_peers -= osize;
	}
    }
    p = n->peers + n->n_peers;
    p->peername = netdbPeerName(e->host);
    n->n_peers++;
    return p;
}

static int
sortPeerByRtt(const void *A, const void *B)
{
    const net_db_peer *p1 = A;
    const net_db_peer *p2 = B;
    if (p1->rtt > p2->rtt)
	return 1;
    else if (p1->rtt < p2->rtt)
	return -1;
    else
	return 0;
}

static void
netdbSaveState(void *foo)
{
    LOCAL_ARRAY(char, path, SQUID_MAXPATHLEN);
    FILE *fp;
    netdbEntry *n;
    netdbEntry *next;
    net_db_name *x;
    struct timeval start = current_time;
    int count = 0;
    snprintf(path, SQUID_MAXPATHLEN, "%s/netdb_state", storeSwapDir(0));
    fp = fopen(path, "w");
    if (fp == NULL) {
	debug(50, 1) ("netdbSaveState: %s: %s\n", path, xstrerror());
	return;
    }
    next = (netdbEntry *) hash_first(addr_table);
    while ((n = next) != NULL) {
	next = (netdbEntry *) hash_next(addr_table);
	if (n->pings_recv == 0)
	    continue;
	fprintf(fp, "%s %d %d %10.5f %10.5f %d %d",
	    n->network,
	    n->pings_sent,
	    n->pings_recv,
	    n->hops,
	    n->rtt,
	    (int) n->next_ping_time,
	    (int) n->last_use_time);
	for (x = n->hosts; x; x = x->next)
	    fprintf(fp, " %s", x->name);
	fprintf(fp, "\n");
	count++;
    }
    fclose(fp);
    getCurrentTime();
    debug(37, 0) ("NETDB state saved; %d entries, %d msec\n",
	count, tvSubMsec(start, current_time));
    eventAdd("netdbSaveState", netdbSaveState, NULL, 3617);
}

static void
netdbReloadState(void)
{
    LOCAL_ARRAY(char, path, SQUID_MAXPATHLEN);
    char *buf = memAllocate(MEM_4K_BUF);
    char *t;
    FILE *fp;
    netdbEntry *n;
    netdbEntry N;
    struct in_addr addr;
    int count = 0;
    struct timeval start = current_time;
    snprintf(path, SQUID_MAXPATHLEN, "%s/netdb_state", storeSwapDir(0));
    fp = fopen(path, "r");
    if (fp == NULL)
	return;
    while (fgets(buf, 4095, fp)) {
	memset(&N, '\0', sizeof(netdbEntry));
	if ((t = strtok(buf, w_space)) == NULL)
	    continue;
	if (!safe_inet_addr(t, &addr))
	    continue;
	if (netdbLookupAddr(addr) != NULL)	/* no dups! */
	    continue;
	if ((t = strtok(NULL, w_space)) == NULL)
	    continue;
	N.pings_sent = atoi(t);
	if ((t = strtok(NULL, w_space)) == NULL)
	    continue;
	N.pings_recv = atoi(t);
	if (N.pings_recv == 0)
	    continue;
	/* give this measurement low weight */
	N.pings_sent = 1;
	N.pings_recv = 1;
	if ((t = strtok(NULL, w_space)) == NULL)
	    continue;
	N.hops = atof(t);
	if ((t = strtok(NULL, w_space)) == NULL)
	    continue;
	N.rtt = atof(t);
	if ((t = strtok(NULL, w_space)) == NULL)
	    continue;
	N.next_ping_time = (time_t) atoi(t);
	if ((t = strtok(NULL, w_space)) == NULL)
	    continue;
	N.last_use_time = (time_t) atoi(t);
	n = memAllocate(MEM_NETDBENTRY);
	xmemcpy(n, &N, sizeof(netdbEntry));
	netdbHashInsert(n, addr);
	while ((t = strtok(NULL, w_space)) != NULL) {
	    if (netdbLookupHost(t) != NULL)	/* no dups! */
		continue;
	    netdbHostInsert(n, t);
	}
	count++;
    }
    memFree(MEM_4K_BUF, buf);
    fclose(fp);
    getCurrentTime();
    debug(37, 0) ("NETDB state reloaded; %d entries, %d msec\n",
	count, tvSubMsec(start, current_time));
}

static char *
netdbPeerName(const char *name)
{
    wordlist *w;
    for (w = peer_names; w; w = w->next) {
	if (!strcmp(w->key, name))
	    return w->key;
    }
    w = xcalloc(1, sizeof(wordlist));
    w->key = xstrdup(name);
    *peer_names_tail = w;
    peer_names_tail = &w->next;
    return w->key;
}



#endif /* USE_ICMP */

/* PUBLIC FUNCTIONS */

void
netdbInit(void)
{
#if USE_ICMP
    if (addr_table)
	return;
    addr_table = hash_create((HASHCMP *) strcmp, 229, hash_string);
    host_table = hash_create((HASHCMP *) strcmp, 467, hash_string);
    eventAdd("netdbSaveState", netdbSaveState, NULL, 3617);
    netdbReloadState();
    cachemgrRegister("netdb",
	"Network Measurement Database",
	netdbDump, 0);
#endif
}

void
netdbPingSite(const char *hostname)
{
#if USE_ICMP
    netdbEntry *n;
    char *h;
    if ((n = netdbLookupHost(hostname)) != NULL)
	if (n->next_ping_time > squid_curtime)
	    return;
    h = xstrdup(hostname);
    cbdataAdd(h, MEM_NONE);
    cbdataLock(h);
    ipcache_nbgethostbyname(hostname, netdbSendPing, h);
#endif
}

void
netdbHandlePingReply(const struct sockaddr_in *from, int hops, int rtt)
{
#if USE_ICMP
    netdbEntry *n;
    int N;
    debug(37, 3) ("netdbHandlePingReply: from %s\n", inet_ntoa(from->sin_addr));
    if ((n = netdbLookupAddr(from->sin_addr)) == NULL)
	return;
    N = ++n->pings_recv;
    if (N > 5)
	N = 5;
    n->hops = ((n->hops * (N - 1)) + hops) / N;
    n->rtt = ((n->rtt * (N - 1)) + rtt) / N;
    debug(37, 3) ("netdbHandlePingReply: %s; rtt=%5.1f  hops=%4.1f\n",
	n->network,
	n->rtt,
	n->hops);
#endif
}

void
netdbFreeMemory(void)
{
#if USE_ICMP
    netdbEntry *n;
    netdbEntry **L1;
    net_db_name **L2;
    net_db_name *x;
    int i = 0;
    int j;
    L1 = xcalloc(memInUse(MEM_NETDBENTRY), sizeof(netdbEntry *));
    n = (netdbEntry *) hash_first(addr_table);
    while (n && i < memInUse(MEM_NETDBENTRY)) {
	*(L1 + i) = n;
	i++;
	n = (netdbEntry *) hash_next(addr_table);
    }
    for (j = 0; j < i; j++) {
	n = *(L1 + j);
	safe_free(n->peers);
	memFree(MEM_NETDBENTRY, n);
    }
    xfree(L1);
    i = 0;
    L2 = xcalloc(memInUse(MEM_NET_DB_NAME), sizeof(net_db_name *));
    x = (net_db_name *) hash_first(host_table);
    while (x && i < memInUse(MEM_NET_DB_NAME)) {
	*(L2 + i) = x;
	i++;
	x = (net_db_name *) hash_next(host_table);
    }
    for (j = 0; j < i; j++) {
	x = *(L2 + j);
	xfree(x->name);
	memFree(MEM_NET_DB_NAME, x);
    }
    xfree(L2);
    hashFreeMemory(addr_table);
    hashFreeMemory(host_table);
    addr_table = NULL;
    host_table = NULL;
    wordlistDestroy(&peer_names);
    peer_names = NULL;
    peer_names_tail = &peer_names;
#endif
}

int
netdbHops(struct in_addr addr)
{
#if USE_ICMP
    netdbEntry *n = netdbLookupAddr(addr);
    if (n && n->pings_recv) {
	n->last_use_time = squid_curtime;
	return (int) (n->hops + 0.5);
    }
#endif
    return 256;
}

void
netdbDump(StoreEntry * sentry)
{
#if USE_ICMP
    netdbEntry *n;
    netdbEntry **list;
    net_db_name *x;
    int k;
    int i;
    int j;
    net_db_peer *p;
    storeAppendPrintf(sentry, "Network DB Statistics:\n");
    storeAppendPrintf(sentry, "%-16.16s %9s %7s %5s %s\n",
	"Network",
	"recv/sent",
	"RTT",
	"Hops",
	"Hostnames");
    list = xcalloc(memInUse(MEM_NETDBENTRY), sizeof(netdbEntry *));
    i = 0;
    n = (netdbEntry *) hash_first(addr_table);
    while (n != NULL) {
	*(list + i++) = n;
	n = (netdbEntry *) hash_next(addr_table);
    }
    if (i != memInUse(MEM_NETDBENTRY))
	debug(37, 0) ("WARNING: netdb_addrs count off, found %d, expected %d\n",
	    i, memInUse(MEM_NETDBENTRY));
    qsort((char *) list,
	i,
	sizeof(netdbEntry *),
	sortByRtt);
    for (k = 0; k < i; k++) {
	n = *(list + k);
	storeAppendPrintf(sentry, "%-16.16s %4d/%4d %7.1f %5.1f",
	    n->network,
	    n->pings_recv,
	    n->pings_sent,
	    n->rtt,
	    n->hops);
	for (x = n->hosts; x; x = x->next)
	    storeAppendPrintf(sentry, " %s", x->name);
	storeAppendPrintf(sentry, "\n");
	p = n->peers;
	for (j = 0; j < n->n_peers; j++, p++) {
	    storeAppendPrintf(sentry, "    %-22.22s %7.1f %5.1f\n",
		p->peername,
		p->rtt,
		p->hops);
	}
    }
    xfree(list);
#else
    storeAppendPrintf(sentry,
	"NETDB support not compiled into this Squid cache.\n");
#endif
}

int
netdbHostHops(const char *host)
{
#if USE_ICMP
    netdbEntry *n = netdbLookupHost(host);
    if (n) {
	n->last_use_time = squid_curtime;
	return (int) (n->hops + 0.5);
    }
#endif
    return 0;
}

int
netdbHostRtt(const char *host)
{
#if USE_ICMP
    netdbEntry *n = netdbLookupHost(host);
    if (n) {
	n->last_use_time = squid_curtime;
	return (int) (n->rtt + 0.5);
    }
#endif
    return 0;
}

void
netdbUpdatePeer(request_t * r, peer * e, int irtt, int ihops)
{
#if USE_ICMP
    netdbEntry *n;
    double rtt = (double) irtt;
    double hops = (double) ihops;
    net_db_peer *p;
    debug(37, 3) ("netdbUpdatePeer: '%s', %d hops, %d rtt\n", r->host, ihops, irtt);
    n = netdbLookupHost(r->host);
    if (n == NULL) {
	debug(37, 3) ("netdbUpdatePeer: host '%s' not found\n", r->host);
	return;
    }
    if ((p = netdbPeerByName(n, e->host)) == NULL)
	p = netdbPeerAdd(n, e);
    p->rtt = rtt;
    p->hops = hops;
    p->expires = squid_curtime + 3600;
    if (n->n_peers < 2)
	return;
    qsort((char *) n->peers,
	n->n_peers,
	sizeof(net_db_peer),
	sortPeerByRtt);
#endif
}

#ifdef SQUID_SNMP
int
netdb_getMax()
{
    int i = 0;
#if USE_ICMP
    static netdbEntry *n = NULL;

    n = (netdbEntry *) hash_first(addr_table);
    if (n != NULL) {
	i = 1;
	while ((n = (netdbEntry *) hash_next(addr_table)))
	    i++;
    }
#endif
    return i;
}

variable_list *
snmp_netdbFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    int cnt;
    static netdbEntry *n = NULL;
#if USE_ICMP
    struct in_addr addr;
#endif
    debug(49, 5) ("snmp_netdbFn: Processing request with %d.%d!\n", Var->name[10],
	Var->name[11]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    cnt = Var->name[11];
#if USE_ICMP
    n = (netdbEntry *) hash_first(addr_table);

    while (n != NULL)
	if (--cnt != 0)
	    n = (netdbEntry *) hash_next(addr_table);
	else
	    break;
#endif
    if (n == NULL) {
	debug(49, 8) ("snmp_netdbFn: Requested past end of netdb table.\n");
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
#if USE_ICMP
    Answer->val_len = sizeof(long);
    Answer->val.integer = xmalloc(Answer->val_len);
    switch (Var->name[10]) {
    case NETDB_ID:
	Answer->type = SMI_INTEGER;
	*(Answer->val.integer) = (long) Var->name[11];
	break;
    case NETDB_NET:
	Answer->type = SMI_IPADDRESS;
	safe_inet_addr(n->network, &addr);
	*(Answer->val.integer) = addr.s_addr;
	break;
    case NETDB_PING_S:
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = (long) n->pings_sent;
	break;
    case NETDB_PING_R:
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = (long) n->pings_recv;
	break;
    case NETDB_HOPS:
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = (long) n->hops;
	break;
    case NETDB_RTT:
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = (long) n->rtt;
	break;
    case NETDB_PINGTIME:
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = (long) n->next_ping_time - squid_curtime;
	break;
    case NETDB_LASTUSE:
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = (long) squid_curtime - n->last_use_time;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
#endif
    return Answer;
}
#endif

void
netdbDeleteAddrNetwork(struct in_addr addr)
{
#if USE_ICMP
    netdbEntry *n = netdbLookupAddr(addr);
    if (n == NULL)
	return;
    debug(37, 1) ("netdbDeleteAddrNetwork: %s\n", n->network);
    netdbRelease(n);
#endif
}
