/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "client_db.h"

#define STUB_API "client_db.cc"
#include "tests/STUB.h"

class ClientInfo;

void clientdbInit(void) STUB
void clientdbUpdate(const Ip::Address &, const LogTags &, AnyP::ProtocolType, size_t) STUB
int clientdbCutoffDenied(const Ip::Address &) STUB_RETVAL(-1)
void clientdbDump(StoreEntry *) STUB
void clientdbFreeMemory(void) STUB
int clientdbEstablished(const Ip::Address &, int) STUB_RETVAL(-1)
#if USE_DELAY_POOLS
void clientdbSetWriteLimiter(ClientInfo * info, const int writeSpeedLimit,const double initialBurst,const double highWatermark) STUB
ClientInfo *clientdbGetInfo(const Ip::Address &addr) STUB_RETVAL(NULL)
#endif
void clientOpenListenSockets(void) STUB
void clientHttpConnectionsClose(void) STUB

