
#include "squid.h"

#define NET_DB_TTL 3600

static HashID table;

static void
netdbHashInsert(netdbEntry * n, char *key)
{
    hash_insert(table, key, n);
    meta_data.netdb++;
    n->link_count++;
}

static void
netdbHashDelete(netdbEntry * n, char *key)
{
    hash_link *hptr = hash_lookup(table, key);
    if (hptr == NULL) {
	debug_trap("netdbHashDelete: key not found");
	return;
    }
    hash_delete_link(table, hptr);
    meta_data.netdb--;
    n->link_count--;
}

static netdbEntry *
netdbCreate(char *network)
{
    netdbEntry *n = xcalloc(1, sizeof(netdbEntry));
    strncpy(n->network, network, 15);
    n->expires = squid_curtime + NET_DB_TTL;
    return n;
}

netdbEntry *
netdbLookup(char *key)
{
    hash_link *hptr = hash_lookup(table, key);
    return hptr ? (netdbEntry *) hptr->item : NULL;
}

static void
netdbAdd(int fdunused, struct hostent *hp, void *data)
{
    netdbEntry *n;
    LOCAL_ARRAY(char, network, 16);
    char *hostname = data;
    if (hp == NULL)
	return;
    strcpy(network, inet_ntoa(inaddrFromHostent(hp)));
    if ((n = netdbLookup(network)) == NULL) {
	n = netdbCreate(network);
	netdbHashInsert(n, network);
    }
    netdbHashInsert(n, hostname);
    xfree(hostname);
}

static void
netdbMaybeAdd(char *hostname)
{
    netdbEntry *n;
    if ((n = netdbLookup(hostname)) != NULL)
	return;
    ipcache_nbgethostbyname(hostname,
	-1,
	netdbAdd,
	(void *) xstrdup(hostname));
}
