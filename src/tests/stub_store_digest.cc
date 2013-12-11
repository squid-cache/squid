#include "squid.h"

#define STUB_API "store_digets.cc"
#include "tests/STUB.h"

class StoreEntry;
void storeDigestInit(void) STUB
void storeDigestNoteStoreReady(void) STUB
void storeDigestDel(const StoreEntry *) STUB
void storeDigestReport(StoreEntry *) STUB
