/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#define STUB_API "icmp/libicmp.la"
#include "STUB.h"

#include "icmp/IcmpSquid.h"
//IcmpSquid::IcmpSquid() STUB
//IcmpSquid::~IcmpSquid() STUB
int IcmpSquid::Open() STUB_RETVAL(-1)
void IcmpSquid::Close() STUB
void IcmpSquid::DomainPing(Ip::Address &to, const char *domain) STUB
#if USE_ICMP
void IcmpSquid::SendEcho(Ip::Address &to, int opcode, const char* payload, int len) STUB
void IcmpSquid::Recv(void) STUB
#endif
//IcmpSquid icmpEngine;

#include "icmp/net_db.h"
void netdbInit(void) STUB
void netdbHandlePingReply(const Ip::Address &from, int hops, int rtt) STUB
void netdbPingSite(const char *hostname) STUB
void netdbDump(StoreEntry *) STUB
void netdbFreeMemory(void) STUB
int netdbHostHops(const char *host) STUB_RETVAL(-1)
int netdbHostRtt(const char *host) STUB_RETVAL(-1)
void netdbUpdatePeer(HttpRequest *, CachePeer * e, int rtt, int hops) STUB
void netdbDeleteAddrNetwork(Ip::Address &addr) STUB
void netdbBinaryExchange(StoreEntry *) STUB
void netdbExchangeStart(void *) STUB
void netdbExchangeUpdatePeer(Ip::Address &, CachePeer *, double, double) STUB
CachePeer *netdbClosestParent(HttpRequest *) STUB_RETVAL(NULL)
void netdbHostData(const char *host, int *samp, int *rtt, int *hops) STUB

