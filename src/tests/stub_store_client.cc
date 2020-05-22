/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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

int storePendingNClients(const StoreEntry * e)
{
    /* no clients in the tests so far */
    return 0;
}

void StoreEntry::invokeHandlers()
{
    /* do nothing for tests */
}

void
storeLog(int tag, const StoreEntry * e)
{
    /* do nothing for tests - we don't need the log */
}

void storeLogOpen(void) STUB
void storeDigestInit(void) STUB
void storeRebuildStart(void) STUB
void storeReplSetup(void) STUB
bool store_client::memReaderHasLowerOffset(int64_t anOffset) const STUB_RETVAL(false)
void store_client::dumpStats(MemBuf * output, int clientNumber) const STUB
int store_client::getType() const STUB_RETVAL(0)

