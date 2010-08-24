#ifndef ICMP_NET_DB_H
#define ICMP_NET_DB_H

#include "config.h"

namespace Ip
{
class Address;
};

class StoreEntry;
class HttpRequest;

/* for struct peer */
#include "structs.h"


SQUIDCEXTERN void netdbInit(void);

SQUIDCEXTERN void netdbHandlePingReply(const Ip::Address &from, int hops, int rtt);
SQUIDCEXTERN void netdbPingSite(const char *hostname);
void netdbDump(StoreEntry *);

SQUIDCEXTERN void netdbFreeMemory(void);
SQUIDCEXTERN int netdbHostHops(const char *host);
SQUIDCEXTERN int netdbHostRtt(const char *host);
SQUIDCEXTERN void netdbUpdatePeer(HttpRequest *, peer * e, int rtt, int hops);

SQUIDCEXTERN void netdbDeleteAddrNetwork(Ip::Address &addr);
SQUIDCEXTERN void netdbBinaryExchange(StoreEntry *);
SQUIDCEXTERN void netdbExchangeStart(void *);

SQUIDCEXTERN void netdbExchangeUpdatePeer(Ip::Address &, peer *, double, double);
SQUIDCEXTERN peer *netdbClosestParent(HttpRequest *);
SQUIDCEXTERN void netdbHostData(const char *host, int *samp, int *rtt, int *hops);

#endif /* ICMP_NET_DB_H */
