/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "client_db.cc"
#include "tests/STUB.h"

#include "client_db.h"
void clientdbUpdate(const Ip::Address &, const LogTags &, AnyP::ProtocolType, size_t) STUB
int clientdbCutoffDenied(const Ip::Address &) STUB_RETVAL(-1)
void clientdbDump(StoreEntry *) STUB
void clientdbFreeMemory(void) STUB
int clientdbEstablished(const Ip::Address &, int) STUB_RETVAL(-1)
#if USE_DELAY_POOLS
void clientdbSetWriteLimiter(ClientInfo * info, const int writeSpeedLimit,const double initialBurst,const double highWatermark) STUB
ClientInfo *clientdbGetInfo(const Ip::Address &addr) STUB_RETVAL(nullptr)
#endif
#if SQUID_SNMP
Ip::Address *client_entry(Ip::Address *) STUB_RETVAL(nullptr)
variable_list *snmp_meshCtblFn(variable_list *, snint *) STUB_RETVAL(nullptr)
#endif

