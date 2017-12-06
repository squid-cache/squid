/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "CollapsedForwarding.h"
#include "HttpReply.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/Pages.h"
#include "MemObject.h"
#include "mime_header.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "StoreStats.h"
#include "tools.h"
#include "Transients.h"

#include <limits>

/// shared memory segment path to use for Transients map
static const SBuf MapLabel("transients_map");
/// shared memory segment path to use for Transients map extras
static const char *ExtrasLabel = "transients_ex";

Transients::Transients(): map(NULL), locals(NULL)
{
}

Transients::~Transients()
{
    delete map;
    delete locals;
}

void
Transients::init()
{
    const int64_t entryLimit = EntryLimit();
    if (entryLimit <= 0)
        return; // no SMP support or a misconfiguration

    Must(!map);
    map = new TransientsMap(MapLabel);
    map->cleaner = this;

    extras = shm_old(TransientsMapExtras)(ExtrasLabel);

    locals = new Locals(entryLimit, 0);
}

void
Transients::getStats(StoreInfoStats &stats) const
{
#if TRANSIENT_STATS_SUPPORTED
    const size_t pageSize = Ipc::Mem::PageSize();

    stats.mem.shared = true;
    stats.mem.capacity =
        Ipc::Mem::PageLimit(Ipc::Mem::PageId::cachePage) * pageSize;
    stats.mem.size =
        Ipc::Mem::PageLevel(Ipc::Mem::PageId::cachePage) * pageSize;
    stats.mem.count = currentCount();
#endif
}

void
Transients::stat(StoreEntry &e) const
{
    storeAppendPrintf(&e, "\n\nTransient Objects\n");

    storeAppendPrintf(&e, "Maximum Size: %.0f KB\n", maxSize()/1024.0);
    storeAppendPrintf(&e, "Current Size: %.2f KB %.2f%%\n",
                      currentSize() / 1024.0,
                      Math::doublePercent(currentSize(), maxSize()));

    if (map) {
        const int limit = map->entryLimit();
        storeAppendPrintf(&e, "Maximum entries: %9d\n", limit);
        if (limit > 0) {
            storeAppendPrintf(&e, "Current entries: %" PRId64 " %.2f%%\n",
                              currentCount(), (100.0 * currentCount() / limit));
        }
    }
}

void
Transients::maintain()
{
    // no lazy garbage collection needed
}

uint64_t
Transients::minSize() const
{
    return 0; // XXX: irrelevant, but Store parent forces us to implement this
}

uint64_t
Transients::maxSize() const
{
    // Squid currently does not limit the total size of all transient objects
    return std::numeric_limits<uint64_t>::max();
}

uint64_t
Transients::currentSize() const
{
    // TODO: we do not get enough information to calculate this
    // StoreEntry should update associated stores when its size changes
    return 0;
}

uint64_t
Transients::currentCount() const
{
    return map ? map->entryCount() : 0;
}

int64_t
Transients::maxObjectSize() const
{
    // Squid currently does not limit the size of a transient object
    return std::numeric_limits<uint64_t>::max();
}

void
Transients::reference(StoreEntry &)
{
    // no replacement policy (but the cache(s) storing the entry may have one)
}

bool
Transients::dereference(StoreEntry &)
{
    // no need to keep e in the global store_table for us; we have our own map
    return false;
}

StoreEntry *
Transients::get(const cache_key *key)
{
    if (!map)
        return NULL;

    sfileno index;
    const Ipc::StoreMapAnchor *anchor = map->openForReading(key, index);
    if (!anchor)
        return NULL;

    // If we already have a local entry, the store_table should have found it.
    // Since it did not, the local entry key must have changed from public to
    // private. We still need to keep the private entry around for syncing as
    // its clients depend on it, but we should not allow new clients to join.
    if (StoreEntry *oldE = locals->at(index)) {
        debugs(20, 3, "not joining private " << *oldE);
        assert(EBIT_TEST(oldE->flags, KEY_PRIVATE));
    } else if (StoreEntry *newE = copyFromShm(*anchor, index)) {
        return newE; // keep read lock to receive updates from others
    }

    // private entry or loading failure
    map->closeForReading(index);
    return NULL;
}

StoreEntry *
Transients::copyFromShm(const Ipc::StoreMapAnchor &anchor, const sfileno index)
{
    const TransientsMapExtras::Item &extra = extras->items[index];

    // create a brand new store entry and initialize it with stored info
    StoreEntry *e = storeCreatePureEntry(extra.url, extra.url, extra.reqMethod);

    assert(e->mem_obj);
    e->mem_obj->method = extra.reqMethod;
    e->mem_obj->xitTable.io = MemObject::ioReading;
    e->mem_obj->xitTable.index = index;

    anchor.exportInto(*e);
    return e;
}

StoreEntry *
Transients::findCollapsed(const sfileno index)
{
    if (!map)
        return NULL;

    if (StoreEntry *oldE = locals->at(index)) {
        debugs(20, 5, "found " << *oldE << " at " << index << " in " << MapLabel);
        assert(oldE->mem_obj && oldE->mem_obj->xitTable.index == index);
        return oldE;
    }

    debugs(20, 3, "no entry at " << index << " in " << MapLabel);
    return NULL;
}

bool
Transients::monitorWhileReading(StoreEntry *e, const Store::CacheKey &cacheKey)
{
    if (!e->hasTransients()) {
        if (!addEntry(e, cacheKey))
            return false;
        // keep the entry locked (for reading) to receive remote DELETE events
        map->closeForWriting(e->mem_obj->xitTable.index, true);
        e->mem_obj->xitTable.io = MemObject::ioReading;
    }

    assert(e->hasTransients());
    const auto index = e->mem_obj->xitTable.index;
    if (const auto old = locals->at(index)) {
        assert(old == e);
    } else {
        // We do not lock e because we do not want to prevent its destruction;
        // e is tied to us via mem_obj so we will know when it is destructed.
        locals->at(index) = e;
    }

    return true;
}

bool
Transients::startWriting(StoreEntry *e, const Store::CacheKey &cacheKey)
{
    if (!e->hasTransients()) {
        if (!addEntry(e, cacheKey))
            return false;

        // keep the entry locked for writing but allow reading our updates
        // we also need this entry locked to receive remote DELETE events
        map->startAppending(e->mem_obj->xitTable.index);
    }

    // XXX: Duplicates Transients::monitorWhileReading().
    assert(e->hasTransients());
    const auto index = e->mem_obj->xitTable.index;
    if (const auto old = locals->at(index)) {
        assert(old == e);
    } else {
        // We do not lock e because we do not want to prevent its destruction;
        // e is tied to us via mem_obj so we will know when it is destructed.
        locals->at(index) = e;
    }

    return true;
}

/// either creates a new Transients entry for `e` or returns false
bool
Transients::addEntry(StoreEntry *e, const Store::CacheKey &cacheKey)
{
    assert(e);
    assert(e->mem_obj);
    assert(!e->hasTransients());

    if (!map) {
        debugs(20, 5, "No map to add " << *e);
        return false;
    }

    sfileno index = 0;
    Ipc::StoreMapAnchor *slot = map->openForWriting(cacheKey.key, index);
    if (!slot) {
        return false;
    }

    try {
        if (copyToShm(*e, index, cacheKey)) {
            slot->set(*e, cacheKey.key);
            e->mem_obj->xitTable.io = MemObject::ioWriting;
            e->mem_obj->xitTable.index = index;
            // keep write lock; the caller will decide what to do with it
            return true;
        }
        // fall through to the error handling code
    } catch (const std::exception &x) { // TODO: should we catch ... as well?
        debugs(20, 2, "error keeping entry " << index <<
               ' ' << *e << ": " << x.what());
        // fall through to the error handling code
    }
    map->abortWriting(index);
    return false;
}

/// copies all relevant local data to shared memory
bool
Transients::copyToShm(const StoreEntry &e, const sfileno index,
                      const Store::CacheKey &cacheKey)
{
    TransientsMapExtras::Item &extra = extras->items[index];

    Must(cacheKey.storeId.length() < sizeof(extra.url)); // we have space to store it all, plus 0
    const int urlLen = cacheKey.storeId.copy(&extra.url[0], sizeof(extra.url));
    extra.url[urlLen] = '\0';

    Must(cacheKey.method != Http::METHOD_OTHER);
    extra.reqMethod = cacheKey.method.id();

    return true;
}

void
Transients::noteFreeMapSlice(const Ipc::StoreMapSliceId)
{
    // TODO: we should probably find the entry being deleted and abort it
}

void
Transients::status(const StoreEntry &entry, bool &aborted, bool &waitingToBeFreed) const
{
    assert(map);
    assert(entry.mem_obj);
    const auto idx = entry.mem_obj->xitTable.index;
    const auto &anchor = isWriter(entry) ?
                         map->writeableEntry(idx) : map->readableEntry(idx);
    aborted = anchor.writerHalted;
    waitingToBeFreed = anchor.waitingToBeFreed;
}

void
Transients::completeWriting(const StoreEntry &e)
{
    assert(e.hasTransients());
    assert(isWriter(e));
    map->closeForWriting(e.mem_obj->xitTable.index, true);
    e.mem_obj->xitTable.io = MemObject::ioReading;
}

int
Transients::readers(const StoreEntry &e) const
{
    if (e.hasTransients()) {
        assert(map);
        return map->peekAtEntry(e.mem_obj->xitTable.index).lock.readers;
    }
    return 0;
}

void
Transients::evictCached(StoreEntry &e)
{
    debugs(20, 5, e);
    if (e.hasTransients()) {
        if (map->freeEntry(e.mem_obj->xitTable.index))
            CollapsedForwarding::Broadcast(e);
    } else
    if (const auto key = e.publicKey())
        evictIfFound(key);
}

void
Transients::evictIfFound(const cache_key *key)
{
    if (!map)
        return;

    const sfileno index = map->fileNoByKey(key);
    if (map->freeEntry(index))
        CollapsedForwarding::Broadcast(index, true);
}

void
Transients::disconnect(StoreEntry &entry)
{
    debugs(20, 5, entry);
    if (entry.hasTransients()) {
        auto &xitTable = entry.mem_obj->xitTable;
        assert(map);
        if (isWriter(entry)) {
            map->abortWriting(xitTable.index);
        } else {
            assert(isReader(entry));
            map->closeForReading(xitTable.index);
        }
        locals->at(xitTable.index) = NULL;
        xitTable.index = -1;
        xitTable.io = MemObject::ioDone;
    }
}

/// calculates maximum number of entries we need to store and map
int64_t
Transients::EntryLimit()
{
    // TODO: we should also check whether any SMP-aware caching is configured
    if (!UsingSmp() || !Config.onoff.collapsed_forwarding)
        return 0; // no SMP collapsed forwarding possible or needed

    return Config.collapsed_forwarding_shared_entries_limit;
}

bool
Transients::markedForDeletion(const cache_key *key) const
{
    assert(map);
    return map->markedForDeletion(key);
}

bool
Transients::isReader(const StoreEntry &e) const
{
    return e.mem_obj && e.mem_obj->xitTable.io == MemObject::ioReading;
}

bool
Transients::isWriter(const StoreEntry &e) const
{
    return e.mem_obj && e.mem_obj->xitTable.io == MemObject::ioWriting;
}

/// initializes shared memory segment used by Transients
class TransientsRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    TransientsRr(): mapOwner(NULL), extrasOwner(NULL) {}
    virtual void useConfig();
    virtual ~TransientsRr();

protected:
    virtual void create();

private:
    TransientsMap::Owner *mapOwner;
    Ipc::Mem::Owner<TransientsMapExtras> *extrasOwner;
};

RunnerRegistrationEntry(TransientsRr);

void
TransientsRr::useConfig()
{
    assert(Config.memShared.configured());
    Ipc::Mem::RegisteredRunner::useConfig();
}

void
TransientsRr::create()
{
    if (!Config.onoff.collapsed_forwarding)
        return;

    const int64_t entryLimit = Transients::EntryLimit();
    if (entryLimit <= 0)
        return; // no SMP configured or a misconfiguration

    Must(!mapOwner);
    mapOwner = TransientsMap::Init(MapLabel, entryLimit);
    Must(!extrasOwner);
    extrasOwner = shm_new(TransientsMapExtras)(ExtrasLabel, entryLimit);
}

TransientsRr::~TransientsRr()
{
    delete extrasOwner;
    delete mapOwner;
}

