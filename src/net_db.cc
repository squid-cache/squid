
#if USE_ICMP

#include "squid.h"

#define NET_DB_TTL 300

#define NETDB_LOW_MARK 900
#define NETDB_HIGH_MARK 1000

static HashID addr_table;
static HashID host_table;

static struct in_addr networkFromInaddr _PARAMS((struct in_addr a));
static void netdbRelease _PARAMS((netdbEntry * n));
static netdbEntry *netdbGetFirst _PARAMS((HashID table));
static netdbEntry *netdbGetNext _PARAMS((HashID table));
static void netdbHashInsert _PARAMS((netdbEntry * n, struct in_addr addr));
static void netdbHashDelete _PARAMS((char *key));
static void netdbHashLink _PARAMS((netdbEntry * n, char *hostname));
static void netdbHashUnlink _PARAMS((char *key));
static void netdbPurgeLRU _PARAMS((void));

void
netdbInit(void)
{
    addr_table = hash_create((int (*)_PARAMS((char *, char *))) strcmp, 229, hash_string);
    host_table = hash_create((int (*)_PARAMS((char *, char *))) strcmp, 467, hash_string);
}

static void
netdbHashInsert(netdbEntry * n, struct in_addr addr)
{
    strncpy(n->network, inet_ntoa(networkFromInaddr(addr)), 15);
    n->key = n->network;
    hash_join(addr_table, (hash_link *) n);
    meta_data.netdb_addrs++;
}

static void
netdbHashDelete(char *key)
{
    hash_link *hptr = hash_lookup(addr_table, key);
    if (hptr == NULL) {
	debug_trap("netdbHashDelete: key not found");
	return;
    }
    hash_remove_link(addr_table, hptr);
    meta_data.netdb_addrs--;
}

static void
netdbHashLink(netdbEntry * n, char *hostname)
{
    struct _net_db_name *x = xcalloc(1, sizeof(struct _net_db_name));
    x->name = xstrdup(hostname);
    x->next = n->hosts;
    n->hosts = x;
    hash_insert(host_table, x->name, n);
    n->link_count++;
    meta_data.netdb_hosts++;
}

static void
netdbHashUnlink(char *key)
{
    netdbEntry *n;
    hash_link *hptr = hash_lookup(host_table, key);
    if (hptr == NULL) {
	debug_trap("netdbHashUnlink: key not found");
	return;
    }
    n = (netdbEntry *) hptr->item;
    n->link_count--;
    hash_delete_link(host_table, hptr);
    meta_data.netdb_hosts--;
}

static netdbEntry *
netdbLookupHost(char *key)
{
    hash_link *hptr = hash_lookup(host_table, key);
    return hptr ? (netdbEntry *) hptr->item : NULL;
}

static netdbEntry *
netdbGetFirst(HashID table)
{
    return (netdbEntry *) hash_first(table);
}

static netdbEntry *
netdbGetNext(HashID table)
{
    return (netdbEntry *) hash_next(table);
}

static void
netdbRelease(netdbEntry * n)
{
    struct _net_db_name *x;
    struct _net_db_name *next;
    for (x = n->hosts; x; x = next) {
	next = x->next;
	netdbHashUnlink(x->name);
	safe_free(x->name);
	safe_free(x);
    }
    n->hosts = NULL;
    if (n->link_count == 0) {
	netdbHashDelete(n->network);
	xfree(n);
    }
}

static int
netdbLRU(netdbEntry ** n1, netdbEntry ** n2)
{
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
    list = xcalloc(meta_data.netdb_addrs, sizeof(netdbEntry *));
    for (n = netdbGetFirst(addr_table); n; n = netdbGetNext(addr_table)) {
	*(list + list_count) = n;
	list_count++;
	if (list_count > meta_data.netdb_addrs)
	    fatal_dump("netdbPurgeLRU: list_count overflow");
    }
    qsort((char *) list,
	list_count,
	sizeof(netdbEntry *),
	(QS) netdbLRU);
    for (k = 0; k < list_count; k++) {
	if (meta_data.netdb_addrs < NETDB_LOW_MARK)
	    break;
	netdbRelease(*(list + k));
	removed++;
    }
    xfree(list);
}

static netdbEntry *
netdbLookupAddr(struct in_addr addr)
{
    char *key = inet_ntoa(networkFromInaddr(addr));
    return (netdbEntry *) hash_lookup(addr_table, key);
}

static netdbEntry *
netdbAdd(struct in_addr addr, char *hostname)
{
    netdbEntry *n;
    if (meta_data.netdb_addrs > NETDB_HIGH_MARK)
	netdbPurgeLRU();
    if ((n = netdbLookupAddr(addr)) == NULL) {
	n = xcalloc(1, sizeof(netdbEntry));
	netdbHashInsert(n, addr);
    }
    netdbHashLink(n, hostname);
    return n;
}

static void
netdbSendPing(int fdunused, ipcache_addrs * ia, void *data)
{
    struct in_addr addr;
    char *hostname = data;
    netdbEntry *n;
    if (ia == NULL) {
	xfree(hostname);
	return;
    }
    addr = ia->in_addrs[ia->cur];
    if ((n = netdbLookupHost(hostname)) == NULL)
	n = netdbAdd(addr, hostname);
    debug(37, 3, "netdbSendPing: pinging %s\n", hostname);
    icmpDomainPing(addr, hostname);
    n->pings_sent++;
    n->next_ping_time = squid_curtime + NET_DB_TTL;
    n->last_use_time = squid_curtime;
    xfree(hostname);
}

void
netdbPingSite(char *hostname)
{
    ipcache_nbgethostbyname(hostname,
	-1,
	netdbSendPing,
	(void *) xstrdup(hostname));
}

void
netdbHandlePingReply(struct sockaddr_in *from, int hops, int rtt)
{
    netdbEntry *n;
    int N;
    debug(37, 3, "netdbHandlePingReply: from %s\n", inet_ntoa(from->sin_addr));
    if ((n = netdbLookupAddr(from->sin_addr)) == NULL)
	return;
    N = ++n->n;
    if (N > 100)
	N = 100;
    n->hops = ((n->hops * (N - 1)) + hops) / N;
    n->rtt = ((n->rtt * (N - 1)) + rtt) / N;
    n->pings_recv++;
    debug(37, 3, "netdbHandlePingReply: %s; rtt=%5.1f  hops=%4.1f\n",
	n->network,
	n->rtt,
	n->hops);
}

static struct in_addr
networkFromInaddr(struct in_addr a)
{
    struct in_addr b;
    b.s_addr = ntohl(a.s_addr);
    if (IN_CLASSC(b.s_addr))
	b.s_addr &= IN_CLASSC_NET;
    else if (IN_CLASSB(b.s_addr))
	b.s_addr &= IN_CLASSB_NET;
    else if (IN_CLASSA(b.s_addr))
	b.s_addr &= IN_CLASSA_NET;
    b.s_addr = htonl(b.s_addr);
    return b;
}

static int
sortByHops(netdbEntry ** n1, netdbEntry ** n2)
{
    if ((*n1)->hops > (*n2)->hops)
	return 1;
    else if ((*n1)->hops < (*n2)->hops)
	return -1;
    else
	return 0;
}

void
netdbDump(StoreEntry * sentry)
{
    netdbEntry *n;
    netdbEntry **list;
    struct _net_db_name *x;
    int k;
    int i;
    storeAppendPrintf(sentry, "{Network DB Statistics:\n");
    storeAppendPrintf(sentry, "{%-16.16s %7s %9s %5s %s}\n",
	"Network",
	"recv/sent",
	"RTT",
	"Hops",
	"Hostnames");
    list = xcalloc(meta_data.netdb_addrs, sizeof(netdbEntry *));
    i = 0;
    for (n = netdbGetFirst(addr_table); n; n = netdbGetNext(addr_table))
	*(list + i++) = n;
    qsort((char *) list,
	i,
	sizeof(netdbEntry *),
	(QS) sortByHops);
    for (k = 0; k < i; k++) {
	n = *(list + k);
	storeAppendPrintf(sentry, "{%-16.16s %4d/%4d %7.1f %5.1f",
	    n->network,
	    n->pings_recv,
	    n->pings_sent,
	    n->rtt,
	    n->hops);
	for (x = n->hosts; x; x = x->next)
	    storeAppendPrintf(sentry, " %s", x->name);
	storeAppendPrintf(sentry, close_bracket);
    }
    storeAppendPrintf(sentry, close_bracket);
    xfree(list);
}

int
netdbHops(struct in_addr addr)
{
    netdbEntry *n = netdbLookupAddr(addr);
    if (n && n->pings_recv) {
	n->last_use_time = squid_curtime;
	return (int) (n->hops + 0.5);
    }
    return 256;
}

void
netdbFreeMemory(void)
{
    netdbEntry *e;
    netdbEntry **L1;
    hash_link *h;
    hash_link **L2;
    struct _net_db_name *x;
    int i = 0;
    int j;

    L1 = xcalloc(meta_data.netdb_addrs, sizeof(netdbEntry));
    e = (netdbEntry *) hash_first(addr_table);
    while (e && i < meta_data.netdb_addrs) {
	*(L1 + i) = e;
	i++;
	e = (netdbEntry *) hash_next(addr_table);
    }
    for (j = 0; j < i; j++)
	xfree(*(L1 + j));
    xfree(L1);

    i = 0;
    L2 = xcalloc(meta_data.netdb_hosts, sizeof(netdbEntry));
    h = hash_first(host_table);
    while (h && i < meta_data.netdb_hosts) {
	*(L2 + i) = h;
	i++;
	h = hash_next(host_table);
    }
    for (j = 0; j < i; j++) {
	h = *(L2 + j);
	x = (struct _net_db_name *) h->item;
	xfree(x->name);
	xfree(x);
	xfree(h);
    }
    xfree(L2);

    hashFreeMemory(addr_table);
    hashFreeMemory(host_table);
}

#endif /* USE_ICMP */
