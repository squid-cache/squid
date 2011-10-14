#include "squid.h"

#define STUB_API "StoreStats.cc"
#include "tests/STUB.h"

#include "StoreStats.h"
#include <cstring>

StoreInfoStats::StoreInfoStats() STUB

StoreInfoStats &
StoreInfoStats::operator +=(const StoreInfoStats &stats) STUB_RETVAL(*this)

StoreIoStats::StoreIoStats()
{
    // we have to implement this one because tests/stub_store.cc
    // has a StoreIoStats global
    memset(this, 0, sizeof(*this));
}
