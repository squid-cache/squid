/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "clientdb/libclientdb.la"
#include "tests/STUB.h"

#include "clientdb/Cache.h"
namespace ClientDb {
ClientInfo *Add(const Ip::Address &) STUB_RETVAL(nullptr)
void Update(const Ip::Address &, const LogTags &, AnyP::ProtocolType, size_t) STUB
ClientInfo *Get(const Ip::Address &) STUB_RETVAL(nullptr)
void Prune(void *) STUB
void Report(StoreEntry *) STUB
int Established(const Ip::Address &, int delta) STUB_RETVAL(0)
bool IcpCutoffDenied(const Ip::Address &) STUB_RETVAL(false)
std::map<Ip::Address, ClientInfo::Pointer> Cache;
}

#include "clientdb/ClientInfo.h"
#if USE_DELAY_POOLS
ClientInfo::ClientInfo(const Ip::Address &) : BandwidthBucket(0, 0, 0) {STUB_NOP}
#else
ClientInfo::ClientInfo(const Ip::Address &) {STUB_NOP}
#endif
ClientInfo::~ClientInfo() {}

#include "clientdb/SnmpGadgets.h"
#if SQUID_SNMP
const Ip::Address *client_entry(const Ip::Address *) STUB_RETVAL(nullptr)
variable_list *snmp_meshCtblFn(variable_list *, snint *) STUB_RETVAL(nullptr)
#endif

