/*
 * DEBUG: section 84    Helper process maintenance
 *
 */

#include "squid.h"
#include "MemStore.h"

#define STUB_API "MemStore.cc"
#include "tests/STUB.h"

MemStore::MemStore() STUB
MemStore::~MemStore() STUB
bool MemStore::keepInLocalMemory(const StoreEntry &) const STUB_RETVAL(false)
void MemStore::considerKeeping(StoreEntry &) STUB
void MemStore::reference(StoreEntry &) STUB
void MemStore::maintain() STUB
void MemStore::cleanReadable(const sfileno) STUB
void MemStore::get(String const, STOREGETCLIENT, void *) STUB
void MemStore::init() STUB
void MemStore::getStats(StoreInfoStats&) const STUB
void MemStore::stat(StoreEntry &) const STUB
int MemStore::callback() STUB_RETVAL(0)
StoreEntry *MemStore::get(const cache_key *) STUB_RETVAL(NULL)
uint64_t MemStore::maxSize() const STUB_RETVAL(0)
uint64_t MemStore::minSize() const STUB_RETVAL(0)
uint64_t MemStore::currentSize() const STUB_RETVAL(0)
uint64_t MemStore::currentCount() const STUB_RETVAL(0)
int64_t MemStore::maxObjectSize() const STUB_RETVAL(0)
StoreSearch *MemStore::search(String const, HttpRequest *) STUB_RETVAL(NULL)
bool MemStore::dereference(StoreEntry &, bool) STUB_RETVAL(false)
