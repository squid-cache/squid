/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 84    Helper process maintenance */

#include "squid.h"
#include "MemStore.h"

#define STUB_API "MemStore.cc"
#include "tests/STUB.h"

MemStore::MemStore() STUB
MemStore::~MemStore() STUB
bool MemStore::keepInLocalMemory(const StoreEntry &) const STUB_RETVAL(false)
void MemStore::write(StoreEntry &e) STUB
void MemStore::completeWriting(StoreEntry &e) STUB
void MemStore::unlink(StoreEntry &e) STUB
void MemStore::disconnect(StoreEntry &e) STUB
void MemStore::reference(StoreEntry &) STUB
void MemStore::maintain() STUB
void MemStore::noteFreeMapSlice(const Ipc::StoreMapSliceId) STUB
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
void MemStore::markForUnlink(StoreEntry&) STUB
bool MemStore::anchorCollapsed(StoreEntry&, bool&) STUB_RETVAL(false)
bool MemStore::updateCollapsed(StoreEntry&) STUB_RETVAL(false)

