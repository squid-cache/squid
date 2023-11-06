/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "repl_modules.h"
#include "Store.h"
#include "store_digest.h"
#include "store_log.h"
#include "store_rebuild.h"
#include "StoreClient.h"

#define STUB_API "store_client.cc"
#include "tests/STUB.h"

int storePendingNClients(const StoreEntry *) STUB_RETVAL_NOP(0)
void StoreEntry::invokeHandlers() STUB_NOP
void storeLog(int, const StoreEntry *) STUB_NOP
void storeLogOpen(void) STUB
void storeDigestInit(void) STUB
void storeRebuildStart(void) STUB
void storeReplSetup(void) STUB
void store_client::noteSwapInDone(bool) STUB
#if USE_DELAY_POOLS
int store_client::bytesWanted() const STUB_RETVAL(0)
#endif
void store_client::dumpStats(MemBuf *, int) const STUB
int store_client::getType() const STUB_RETVAL(0)

