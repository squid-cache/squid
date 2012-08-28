#include "squid.h"
#include "StoreMeta.h"

#define STUB_API "store_swapout.cc"
#include "tests/STUB.h"

#include <iostream>

/* XXX: wrong stub file... */
void storeUnlink(StoreEntry * e) STUB

char *storeSwapMetaPack(tlv * tlv_list, int *length) STUB_RETVAL(NULL)
tlv *storeSwapMetaBuild(StoreEntry * e) STUB_RETVAL(NULL)
void storeSwapTLVFree(tlv * n) STUB
