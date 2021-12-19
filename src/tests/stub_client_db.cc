/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
int clientdbEstablished(const Ip::Address &, int) STUB_RETVAL(-1)
ClientInfo *clientdbGetInfo(const Ip::Address &) STUB_RETVAL(nullptr)
#if USE_DELAY_POOLS
void clientdbSetWriteLimiter(ClientInfo *, const int,const double,const double) STUB
#endif
#if SQUID_SNMP
const Ip::Address *client_entry(const Ip::Address *) STUB_RETVAL(nullptr)
variable_list *snmp_meshCtblFn(variable_list *, snint *) STUB_RETVAL(nullptr)
#endif

