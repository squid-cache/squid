/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
    assert(Enabled());
    const int64_t entryLimit = EntryLimit();
    assert(entryLimit > 0);

    Must(!map);
    map = new TransientsMap(MapLabel);
    map->cleaner = this;
    map->disableHitValidation(); // Transients lacks slices to validate

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
        map->closeForReadingAndFreeIdle(index);
        return nullptr;
    }

    StoreEntry *e = new StoreEntry();
    e->createMemObject();
    e->mem_obj->xitTable.index = index;
    e->mem_obj->xitTable.io = Store::ioReading;
    anchor->exportInto(*e);
    const bool collapsingRequired = EBIT_TEST(anchor->basics.flags, ENTRY_REQUIRES_COLLAPSING);
    e->setCollapsingRequirement(collapsingRequired);
    // keep read lock to receive updates from others
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

void
Transients::clearCollapsingRequirement(const StoreEntry &e)
{
    assert(map);
    assert(e.hasTransients());
    assert(isWriter(e));
    const auto idx = e.mem_obj->xitTable.index;
    auto &anchor = map->writeableEntry(idx);
    if (EBIT_TEST(anchor.basics.flags, ENTRY_REQUIRES_COLLAPSING)) {
        EBIT_CLR(anchor.basics.flags, ENTRY_REQUIRES_COLLAPSING);
        CollapsedForwarding::Broadcast(e);
    }
}

void
Transients::monitorIo(StoreEntry *e, const cache_key *key, const Store::IoStatus direction)
{
    if (!e->hasTransients()) {
        addEntry(e, key, direction);
        assert(e->hasTransients());
    }

    const auto index = e->mem_obj->xitTable.index;
    if (const auto old = locals->at(index)) {
        assert(old == e);
    } else {
        // We do not lock e because we do not want to prevent its destruction;
        // e is tied to us via mem_obj so we will know when it is destructed.
        locals->at(index) = e;
    }
}

/// creates a new Transients entry
void
Transients::addEntry(StoreEntry *e, const cache_key *key, const Store::IoStatus direction)
{
    assert(e);
    assert(e->mem_obj);
    assert(!e->hasTransients());

    Must(map); // configured to track transients

    sfileno index = 0;
    Ipc::StoreMapAnchor *slot = map->openForWriting(key, index);
    Must(slot); // no writer collisions

    // set ASAP in hope to unlock the slot if something throws
    e->mem_obj->xitTable.index = index;
    e->mem_obj->xitTable.io = Store::ioWriting;

    slot->set(*e, key);
    if (direction == Store::ioWriting) {
        // allow reading and receive remote DELETE events, but do not switch to
        // the reading lock because transientReaders() callers want true readers
        map->startAppending(index);
    } else {
        assert(direction == Store::ioReading);
        // keep the entry locked (for reading) to receive remote DELETE events
        map->switchWritingToReading(index);
        e->mem_obj->xitTable.io = Store::ioReading;
    }
}

bool
Transients::hasWriter(const StoreEntry &e)
{
    if (!e.hasTransients())
        return false;
    return map->peekAtWriter(e.mem_obj->xitTable.index);
}

void
Transients::noteFreeMapSlice(const Ipc::StoreMapSliceId)
{
    // TODO: we should probably find the entry being deleted and abort it
}

void
Transients::status(const StoreEntry &entry, Transients::EntryStatus &entryStatus) const
{
    assert(map);
    assert(entry.hasTransients());
    const auto idx = entry.mem_obj->xitTable.index;
    const auto &anchor = isWriter(entry) ?
                         map->writeableEntry(idx) : map->readableEntry(idx);
    entryStatus.abortedByWriter = anchor.writerHalted;
    entryStatus.waitingToBeFreed = anchor.waitingToBeFreed;
    entryStatus.collapsed = EBIT_TEST(anchor.basics.flags, ENTRY_REQUIRES_COLLAPSING);
}

void
Transients::completeWriting(const StoreEntry &e)
{
    assert(e.hasTransients());
    assert(isWriter(e));
    map->switchWritingToReading(e.mem_obj->xitTable.index);
    e.mem_obj->xitTable.io = Store::ioReading;
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
        const auto index = e.mem_obj->xitTable.index;
        if (map->freeEntry(index)) {
            // Delay syncCollapsed(index) which may end `e` wait for updates.
            // Calling it directly/here creates complex reentrant call chains.
            CollapsedForwarding::Broadcast(e, true);
        }
    } // else nothing to do because e must be private
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
            map->closeForReadingAndFreeIdle(xitTable.index);
        }
        locals->at(xitTable.index) = nullptr;
        xitTable.index = -1;
        xitTable.io = Store::ioDone;
    }
}

/// calculates maximum number of entries we need to store and map
int64_t
Transients::EntryLimit()
{
    return (UsingSmp() && Store::Controller::SmpAware()) ?
           Config.shared_transient_entries_limit : 0;
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
    return e.mem_obj && e.mem_obj->xitTable.io == Store::ioReading;
}

bool
Transients::isWriter(const StoreEntry &e) const
{
    return e.mem_obj && e.mem_obj->xitTable.io == Store::ioWriting;
}

/// initializes shared memory segment used by Transients
class TransientsRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void useConfig();
    virtual ~TransientsRr();

protected:
    virtual void create();

private:
    TransientsMap::Owner *mapOwner = nullptr;
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
    const int64_t entryLimit = Transients::EntryLimit();
    if (entryLimit <= 0)
        return; // no SMP configured or a misconfiguration

    Must(!mapOwner);
    mapOwner = TransientsMap::Init(MapLabel, entryLimit);
}

TransientsRr::~TransientsRr()
{
    delete mapOwner;
}

