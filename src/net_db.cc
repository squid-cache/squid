
#if USE_ICMP

#include "squid.h"

#define NET_DB_TTL 5

static HashID addr_table;
static HashID host_table;

static struct in_addr networkFromInaddr _PARAMS((struct in_addr a));

void
netdbInit(void)
{
    addr_table = hash_create(strcmp, 229, hash_string);
    host_table = hash_create(strcmp, 467, hash_string);
}

static void
netdbHashInsert(netdbEntry * n, struct in_addr addr)
{
    strncpy(n->network, inet_ntoa(networkFromInaddr(addr)), 15);
    n->key = n->network;
    hash_join(addr_table, (hash_link *) n);
    meta_data.netdb++;
}

static void
netdbHashDelete(struct in_addr addr)
{
    char *key = inet_ntoa(networkFromInaddr(addr));
    hash_link *hptr = hash_lookup(addr_table, key);
    if (hptr == NULL) {
	debug_trap("netdbHashDelete: key not found");
	return;
    }
    hash_delete_link(addr_table, hptr);
    meta_data.netdb--;
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
    hash_delete(host_table, hptr);
    meta_data.netdb--;
    n = (netdbEntry *) hptr->item;
    n->link_count--;
}

static netdbEntry *
netdbLookupHost(char *key)
{
    hash_link *hptr = hash_lookup(host_table, key);
    return hptr ? (netdbEntry *) hptr->item : NULL;
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
    if ((n = netdbLookupAddr(addr)) == NULL) {
	n = xcalloc(1, sizeof(netdbEntry));
	netdbHashInsert(n, addr);
    }
    netdbHashLink(n, hostname);
    return n;
}

static void
netdbSendPing(int fdunused, struct hostent *hp, void *data)
{
    struct in_addr addr;
    char *hostname = data;
    netdbEntry *n;
    if (hp == NULL)
	return;
    addr = inaddrFromHostent(hp);
    if ((n = netdbLookupHost(hostname)) == NULL)
	n = netdbAdd(addr, hostname);
    debug(37, 0, "netdbSendPing: pinging %s\n", hostname);
    icmpDomainPing(addr, hostname);
    n->next_ping_time = squid_curtime + NET_DB_TTL;
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
    debug(37, 0, "netdbHandlePingReply: from %s\n", inet_ntoa(from->sin_addr));
    if ((n = netdbLookupAddr(from->sin_addr)) == NULL)
	return;
    N = ++n->n;
    if (N > 100)
	N = 100;
    n->hops = ((n->hops * (N - 1)) + hops) / N;
    n->rtt = ((n->rtt * (N - 1)) + rtt) / N;
    debug(37, 0, "netdbHandlePingReply: %s; rtt=%5.1f  hops=%4.1f\n",
	n->network,
	n->rtt,
	n->hops);
}

static struct in_addr
networkFromInaddr(struct in_addr a)
{
    struct in_addr b = a;
    if (IN_CLASSC(b.s_addr))
	b.s_addr &= IN_CLASSC_NET;
    else if (IN_CLASSB(b.s_addr))
	b.s_addr &= IN_CLASSB_NET;
    else if (IN_CLASSA(b.s_addr))
	b.s_addr &= IN_CLASSA_NET;
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
    storeAppendPrintf(sentry, "{%-16.16s %7s %5s %s}\n",
	"Network",
	"RTT",
	"Hops",
	"Hostnames");
    list = xcalloc(meta_data.netdb, sizeof(netdbEntry *));
    n = (netdbEntry *) hash_first(addr_table);
    i = 0;
    while (n) {
	*(list + i++) = n;
	n = (netdbEntry *) hash_next(addr_table);
    }
    qsort((char *) list,
	i,
	sizeof(netdbEntry *),
	(QS) sortByHops);
    for (k = 0; k < i; k++) {
	n = *(list + k);
	storeAppendPrintf(sentry, "{%-16.16s %7.1f %5.1f",
	    n->network,
	    n->rtt,
	    n->hops);
	for (x = n->hosts; x; x = x->next)
	    storeAppendPrintf(sentry, " %s", x->name);
	storeAppendPrintf(sentry, close_bracket);
    }
    storeAppendPrintf(sentry, close_bracket);
    xfree(list);
}

#endif /* USE_ICMP */
