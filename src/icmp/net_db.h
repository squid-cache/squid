/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef ICMP_NET_DB_H
#define ICMP_NET_DB_H

#include "hash.h"

class CachePeer;
class HttpRequest;
class netdbEntry;
class StoreEntry;
namespace Ip
{
class Address;
};

// POD
class net_db_name
{
public:
    hash_link hash;     /* must be first */
    net_db_name *next;
    netdbEntry *net_db_entry;
};

// POD
class net_db_peer
{
public:
    const char *peername;
    double hops;
    double rtt;
    time_t expires;
};

// POD
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

void netdbInit(void);

void netdbHandlePingReply(const Ip::Address &from, int hops, int rtt);
void netdbPingSite(const char *hostname);
void netdbDump(StoreEntry *);

void netdbFreeMemory(void);
int netdbHostHops(const char *host);
int netdbHostRtt(const char *host);
void netdbUpdatePeer(HttpRequest *, CachePeer * e, int rtt, int hops);

void netdbDeleteAddrNetwork(Ip::Address &addr);
void netdbBinaryExchange(StoreEntry *);
void netdbExchangeStart(void *);

void netdbExchangeUpdatePeer(Ip::Address &, CachePeer *, double, double);
CachePeer *netdbClosestParent(HttpRequest *);
void netdbHostData(const char *host, int *samp, int *rtt, int *hops);

#endif /* ICMP_NET_DB_H */

