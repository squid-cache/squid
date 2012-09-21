#ifndef ICMP_NET_DB_H
#define ICMP_NET_DB_H

#include "hash.h"

class CachePeer;
namespace Ip
{
class Address;
};

class StoreEntry;
class HttpRequest;
class netdbEntry;

class net_db_name
{
public:
    hash_link hash;     /* must be first */
    net_db_name *next;
    netdbEntry *net_db_entry;
};

class net_db_peer
{
public:
    const char *peername;
    double hops;
    double rtt;
    time_t expires;
};

class netdbEntry
{
public:
    hash_link hash;     /* must be first */
    char network[MAX_IPSTRLEN];
    int pings_sent;
    int pings_recv;
    double hops;
    double rtt;
    time_t next_ping_time;
    time_t last_use_time;
    int link_count;
    net_db_name *hosts;
    net_db_peer *peers;
    int n_peers_alloc;
    int n_peers;
};

extern void netdbInit(void);

extern void netdbHandlePingReply(const Ip::Address &from, int hops, int rtt);
extern void netdbPingSite(const char *hostname);
void netdbDump(StoreEntry *);

extern void netdbFreeMemory(void);
extern int netdbHostHops(const char *host);
extern int netdbHostRtt(const char *host);
extern void netdbUpdatePeer(HttpRequest *, CachePeer * e, int rtt, int hops);

extern void netdbDeleteAddrNetwork(Ip::Address &addr);
extern void netdbBinaryExchange(StoreEntry *);
extern void netdbExchangeStart(void *);

extern void netdbExchangeUpdatePeer(Ip::Address &, CachePeer *, double, double);
extern CachePeer *netdbClosestParent(HttpRequest *);
extern void netdbHostData(const char *host, int *samp, int *rtt, int *hops);

#endif /* ICMP_NET_DB_H */
