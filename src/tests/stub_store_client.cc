/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"
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
bool store_client::memReaderHasLowerOffset(int64_t) const STUB_RETVAL(false)
void store_client::dumpStats(MemBuf *, int) const STUB
int store_client::getType() const STUB_RETVAL(0)

