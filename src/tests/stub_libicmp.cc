/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#define STUB_API "icmp/libicmp.la"
#include "tests/STUB.h"

#include "icmp/IcmpSquid.h"
//IcmpSquid::IcmpSquid() STUB
//IcmpSquid::~IcmpSquid() STUB
int IcmpSquid::Open() STUB_RETVAL(-1)
void IcmpSquid::Close() STUB
void IcmpSquid::DomainPing(Ip::Address &, const char *) STUB
#if USE_ICMP
void IcmpSquid::SendEcho(Ip::Address &, int, const char*, int) STUB
void IcmpSquid::Recv(void) STUB
#endif
//IcmpSquid icmpEngine;

#include "icmp/net_db.h"
void netdbInit(void) STUB
void netdbHandlePingReply(const Ip::Address &, int, int) STUB
void netdbPingSite(const char *) STUB
void netdbDump(StoreEntry *) STUB
int netdbHostHops(const char *) STUB_RETVAL(-1)
int netdbHostRtt(const char *) STUB_RETVAL(-1)
void netdbUpdatePeer(const AnyP::Uri &, CachePeer *, int, int) STUB
void netdbDeleteAddrNetwork(Ip::Address &) STUB
void netdbBinaryExchange(StoreEntry *) STUB
void netdbExchangeStart(void *) STUB
void netdbExchangeUpdatePeer(Ip::Address &, CachePeer *, double, double) STUB
CachePeer *netdbClosestParent(PeerSelector *) STUB_RETVAL(nullptr)
void netdbHostData(const char *, int *, int *, int *) STUB

