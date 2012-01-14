#include "squid.h"
#include "StoreClient.h"
#include "Store.h"

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
const char *storeEntryFlags(const StoreEntry *) STUB_RETVAL(NULL)
void storeReplSetup(void) STUB
bool store_client::memReaderHasLowerOffset(int64_t anOffset) const STUB_RETVAL(false)
void store_client::dumpStats(MemBuf * output, int clientNumber) const STUB
int store_client::getType() const STUB_RETVAL(0)
