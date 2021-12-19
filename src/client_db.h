/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Client Database */

#ifndef SQUID_CLIENT_DB_H_
#define SQUID_CLIENT_DB_H_

#include "anyp/ProtocolType.h"
#include "base/Packable.h"
#include "ip/Address.h"
#include "LogTags.h"
#if SQUID_SNMP
#include "cache_snmp.h"
#include "snmp_vars.h"
#endif

namespace Ip
{
class Address;
}

class ClientInfo;

void clientdbUpdate(const Ip::Address &, const LogTags &, AnyP::ProtocolType, size_t);
int clientdbCutoffDenied(const Ip::Address &);
int clientdbEstablished(const Ip::Address &, int);
ClientInfo *clientdbGetInfo(const Ip::Address &);

#if USE_DELAY_POOLS
void clientdbSetWriteLimiter(ClientInfo * info, const int writeSpeedLimit,const double initialBurst,const double highWatermark);
#endif

#if SQUID_SNMP
const Ip::Address *client_entry(const Ip::Address *current);
variable_list *snmp_meshCtblFn(variable_list *, snint *);
#endif

#endif /* SQUID_CLIENT_DB_H_ */

