/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Controller */

#include "squid.h"
#include "mem_node.h"
#include "MemStore.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "store/Controller.h"
#include "store/Disks.h"
#include "store/LocalSearch.h"
#include "tools.h"
#include "Transients.h"

#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

/*
 * store_dirs_rebuilding is initialized to _1_ as a hack so that
 * storeDirWriteCleanLogs() doesn't try to do anything unless _all_
 * cache_dirs have been read.  For example, without this hack, Squid
 * will try to write clean log files if -kparse fails (because it
 * calls fatal()).
 */
int Store::Controller::store_dirs_rebuilding = 1;

Store::Controller::Controller() :
    swapDir(new Disks),
    sharedMemStore(nullptr),
    localMemStore(false),
    transients(NULL)
{
    assert(!store_table);
}

Store::Controller::~Controller()
{
    delete sharedMemStore;
    delete transients;
    delete swapDir;

    if (store_table) {
        hashFreeItems(store_table, destroyStoreEntry);
        hashFreeMemory(store_table);
        store_table = nullptr;
    }
}

void
Store::Controller::init()
{
    if (IamWorkerProcess()) {
        if (MemStore::Enabled()) {
            sharedMemStore = new MemStore;
            sharedMemStore->init();
        } else if (Config.memMaxSize > 0) {
            localMemStore = true;
        }
    }

    swapDir->init();

    if (Transients::Enabled() && IamWorkerProcess()) {
        transients = new Transients;
        transients->init();
    }
}

void
Store::Controller::create()
{
    swapDir->create();

#if !_SQUID_WINDOWS_
    pid_t pid;
    do {
        PidStatus status;
        pid = WaitForAnyPid(status, WNOHANG);
    } while (pid > 0 || (pid < 0 && errno == EINTR));
#endif
}

void
Store::Controller::maintain()
{
    static time_t last_warn_time = 0;

    PROF_start(storeMaintainSwapSpace);
    swapDir->maintain();

    /* this should be emitted by the oversize dir, not globally */

    if (Root().currentSize() > Store::Root().maxSize()) {
        if (squid_curtime - last_warn_time > 10) {
            debugs(20, DBG_CRITICAL, "WARNING: Disk space over limit: "
                   << Store::Root().currentSize() / 1024.0 << " KB > "
                   << (Store::Root().maxSize() >> 10) << " KB");
            last_warn_time = squid_curtime;
        }
    }

    PROF_stop(storeMaintainSwapSpace);
}

void
Store::Controller::getStats(StoreInfoStats &stats) const
{
    if (sharedMemStore)
        sharedMemStore->getStats(stats);
    else {
        // move this code to a non-shared memory cache class when we have it
        stats.mem.shared = false;
        stats.mem.capacity = Config.memMaxSize;
        stats.mem.size = mem_node::StoreMemSize();
        if (localMemStore) {
            // XXX: also count internal/in-transit objects
            stats.mem.count = hot_obj_count;
        } else {
            // XXX: count internal/in-transit objects instead
            stats.mem.count = hot_obj_count;
        }
    }

    swapDir->getStats(stats);

    // low-level info not specific to memory or disk cache
    stats.store_entry_count = StoreEntry::inUseCount();
    stats.mem_object_count = MemObject::inUseCount();
}

void
Store::Controller::stat(StoreEntry &output) const
{
    storeAppendPrintf(&output, "Store Directory Statistics:\n");
    storeAppendPrintf(&output, "Store Entries          : %lu\n",
                      (unsigned long int)StoreEntry::inUseCount());
    storeAppendPrintf(&output, "Maximum Swap Size      : %" PRIu64 " KB\n",
                      maxSize() >> 10);
    storeAppendPrintf(&output, "Current Store Swap Size: %.2f KB\n",
                      currentSize() / 1024.0);
    storeAppendPrintf(&output, "Current Capacity       : %.2f%% used, %.2f%% free\n",
                      Math::doublePercent(currentSize(), maxSize()),
                      Math::doublePercent((maxSize() - currentSize()), maxSize()));

    if (sharedMemStore)
        sharedMemStore->stat(output);

    /* now the swapDir */
    swapDir->stat(output);
}

/* if needed, this could be taught to cache the result */
uint64_t
Store::Controller::maxSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->maxSize();
}

uint64_t
Store::Controller::minSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->minSize();
}

uint64_t
Store::Controller::currentSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->currentSize();
}

uint64_t
Store::Controller::currentCount() const
{
    /* TODO: include memory cache ? */
    return swapDir->currentCount();
}

int64_t
Store::Controller::maxObjectSize() const
{
    /* TODO: include memory cache ? */
    return swapDir->maxObjectSize();
}

void
Store::Controller::updateLimits()
{
    swapDir->updateLimits();

    store_swap_high = (long) (((float) maxSize() *
                               (float) Config.Swap.highWaterMark) / (float) 100);
    store_swap_low = (long) (((float) maxSize() *
                              (float) Config.Swap.lowWaterMark) / (float) 100);
    store_pages_max = Config.memMaxSize / sizeof(mem_node);

    // TODO: move this into a memory cache class when we have one
    const int64_t memMax = static_cast<int64_t>(min(Config.Store.maxInMemObjSize, Config.memMaxSize));
    const int64_t disksMax = swapDir ? swapDir->maxObjectSize() : 0;
    store_maxobjsize = std::max(disksMax, memMax);
}

StoreSearch *
Store::Controller::search()
{
    // this is the only kind of search we currently support
    return NewLocalSearch();
}

void
Store::Controller::sync(void)
{
    if (sharedMemStore)
        sharedMemStore->sync();
    swapDir->sync();
}

/*
 * handle callbacks all available fs'es
 */
int
Store::Controller::callback()
{
    /* This will likely double count. That's ok. */
    PROF_start(storeDirCallback);

    /* mem cache callbacks ? */
    int result = swapDir->callback();

    PROF_stop(storeDirCallback);

    return result;
}

/// update reference counters of the recently touched entry
void
Store::Controller::referenceBusy(StoreEntry &e)
{
    // special entries do not belong to any specific Store, but are IN_MEMORY
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return;

    /* Notify the fs that we're referencing this object again */

    if (e.hasDisk())
        swapDir->reference(e);

    // Notify the memory cache that we're referencing this object again
    if (sharedMemStore && e.mem_status == IN_MEMORY)
        sharedMemStore->reference(e);

    // TODO: move this code to a non-shared memory cache class when we have it
    if (e.mem_obj) {
        if (mem_policy->Referenced)
            mem_policy->Referenced(mem_policy, &e, &e.mem_obj->repl);
    }
}

/// dereference()s an idle entry
/// \returns false if and only if the entry should be deleted
bool
Store::Controller::dereferenceIdle(StoreEntry &e, bool wantsLocalMemory)
{
    // special entries do not belong to any specific Store, but are IN_MEMORY
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return true;

    bool keepInStoreTable = false; // keep only if somebody needs it there

    /* Notify the fs that we're not referencing this object any more */

    if (e.hasDisk())
        keepInStoreTable = swapDir->dereference(e) || keepInStoreTable;

    // Notify the memory cache that we're not referencing this object any more
    if (sharedMemStore && e.mem_status == IN_MEMORY)
        keepInStoreTable = sharedMemStore->dereference(e) || keepInStoreTable;

    // TODO: move this code to a non-shared memory cache class when we have it
    if (e.mem_obj) {
        if (mem_policy->Dereferenced)
            mem_policy->Dereferenced(mem_policy, &e, &e.mem_obj->repl);
        // non-shared memory cache relies on store_table
        if (localMemStore)
            keepInStoreTable = wantsLocalMemory || keepInStoreTable;
    }

    return keepInStoreTable;
}

bool
Store::Controller::markedForDeletion(const cache_key *key) const
{
    // assuming a public key, checking Transients should cover all cases.
    return transients && transients->markedForDeletion(key);
}

bool
Store::Controller::markedForDeletionAndAbandoned(const StoreEntry &e) const
{
    // The opposite check order could miss a reader that has arrived after the
    // !readers() and before the markedForDeletion() check.
    return markedForDeletion(reinterpret_cast<const cache_key*>(e.key)) &&
           transients && !transients->readers(e);
}

bool
Store::Controller::hasReadableDiskEntry(const StoreEntry &e) const
{
    return swapDir->hasReadableEntry(e);
}

StoreEntry *
Store::Controller::find(const cache_key *key)
{
    if (const auto entry = peek(key)) {
        try {
            if (!entry->key)
                allowSharing(*entry, key);
            checkTransients(*entry);
            entry->touch();
            referenceBusy(*entry);
            return entry;
        } catch (const std::exception &ex) {
            debugs(20, 2, "failed with " << *entry << ": " << ex.what());
            entry->release();
            // fall through
        }
    }
    return NULL;
}

/// indexes and adds SMP-tracking for an ephemeral peek() result
void
Store::Controller::allowSharing(StoreEntry &entry, const cache_key *key)
{
    // TODO: refactor to throw on anchorToCache() inSync errors!

    // anchorToCache() below and many find() callers expect a registered entry
    addReading(&entry, key);

    if (entry.hasTransients()) {
        bool inSync = false;
        const bool found = anchorToCache(entry, inSync);
        if (found && !inSync)
            throw TexcHere("cannot sync");
        if (!found) {
            // !found should imply hittingRequiresCollapsing() regardless of writer presence
            if (!entry.hittingRequiresCollapsing()) {
                debugs(20, DBG_IMPORTANT, "BUG: missing ENTRY_REQUIRES_COLLAPSING for " << entry);
                throw TextException("transients entry missing ENTRY_REQUIRES_COLLAPSING", Here());
            }

            if (!transients->hasWriter(entry)) {
                // prevent others from falling into the same trap
                throw TextException("unattached transients entry missing writer", Here());
            }
        }
    }
}

StoreEntry *
Store::Controller::findCallbackXXX(const cache_key *key)
{
    // We could check for mem_obj presence (and more), moving and merging some
    // of the duplicated neighborsUdpAck() and neighborsHtcpReply() code here,
    // but that would mean polluting Store with HTCP/ICP code. Instead, we
    // should encapsulate callback-related data in a protocol-neutral MemObject
    // member or use an HTCP/ICP-specific index rather than store_table.

    // cannot reuse peekAtLocal() because HTCP/ICP callbacks may use private keys
    return static_cast<StoreEntry*>(hash_lookup(store_table, key));
}

/// \returns either an existing local reusable StoreEntry object or nil
/// To treat remotely marked entries specially,
/// callers ought to check markedForDeletion() first!
StoreEntry *
Store::Controller::peekAtLocal(const cache_key *key)
{
    if (StoreEntry *e = static_cast<StoreEntry*>(hash_lookup(store_table, key))) {
        // callers must only search for public entries
        assert(!EBIT_TEST(e->flags, KEY_PRIVATE));
        assert(e->publicKey());
        checkTransients(*e);

        // TODO: ignore and maybe handleIdleEntry() unlocked intransit entries
        // because their backing store slot may be gone already.
        return e;
    }
    return nullptr;
}

StoreEntry *
Store::Controller::peek(const cache_key *key)
{
    debugs(20, 3, storeKeyText(key));

    if (markedForDeletion(key)) {
        debugs(20, 3, "ignoring marked in-transit " << storeKeyText(key));
        return nullptr;
    }

    if (StoreEntry *e = peekAtLocal(key)) {
        debugs(20, 3, "got local in-transit entry: " << *e);
        return e;
    }

    // Must search transients before caches because we must sync those we find.
    if (transients) {
        if (StoreEntry *e = transients->get(key)) {
            debugs(20, 3, "got shared in-transit entry: " << *e);
            return e;
        }
    }

    if (sharedMemStore) {
        if (StoreEntry *e = sharedMemStore->get(key)) {
            debugs(20, 3, HERE << "got mem-cached entry: " << *e);
            return e;
        }
    }

    if (swapDir) {
        if (StoreEntry *e = swapDir->get(key)) {
            debugs(20, 3, "got disk-cached entry: " << *e);
            return e;
        }
    }

    debugs(20, 4, "cannot locate " << storeKeyText(key));
    return nullptr;
}

bool
Store::Controller::transientsReader(const StoreEntry &e) const
{
    return transients && e.hasTransients() && transients->isReader(e);
}

bool
Store::Controller::transientsWriter(const StoreEntry &e) const
{
    return transients && e.hasTransients() && transients->isWriter(e);
}

int64_t
Store::Controller::accumulateMore(StoreEntry &entry) const
{
    return swapDir ? swapDir->accumulateMore(entry) : 0;
    // The memory cache should not influence for-swapout accumulation decision.
}

// Must be called from StoreEntry::release() or releaseRequest() because
// those methods currently manage local indexing of StoreEntry objects.
// TODO: Replace StoreEntry::release*() with Root().evictCached().
void
Store::Controller::evictCached(StoreEntry &e)
{
    debugs(20, 7, e);
    if (transients)
        transients->evictCached(e);
    memoryEvictCached(e);
    if (swapDir)
        swapDir->evictCached(e);
}

void
Store::Controller::evictIfFound(const cache_key *key)
{
    debugs(20, 7, storeKeyText(key));

    if (StoreEntry *entry = peekAtLocal(key)) {
        debugs(20, 5, "marking local in-transit " << *entry);
        entry->release(true);
        return;
    }

    if (sharedMemStore)
        sharedMemStore->evictIfFound(key);
    if (swapDir)
        swapDir->evictIfFound(key);
    if (transients)
        transients->evictIfFound(key);
}

/// whether the memory cache is allowed to store that many additional pages
bool
Store::Controller::memoryCacheHasSpaceFor(const int pagesRequired) const
{
    // XXX: We count mem_nodes but may free shared memory pages instead.
    const auto fits = mem_node::InUseCount() + pagesRequired <= store_pages_max;
    debugs(20, 7, fits << ": " << mem_node::InUseCount() << '+' << pagesRequired << '?' << store_pages_max);
    return fits;
}

void
Store::Controller::freeMemorySpace(const int bytesRequired)
{
    const auto pagesRequired = (bytesRequired + SM_PAGE_SIZE-1) / SM_PAGE_SIZE;

    if (memoryCacheHasSpaceFor(pagesRequired))
        return;

    // XXX: When store_pages_max is smaller than pagesRequired, we should not
    // look for more space (but we do because we want to abandon idle entries?).

    // limit our performance impact to one walk per second
    static time_t lastWalk = 0;
    if (lastWalk == squid_curtime)
        return;
    lastWalk = squid_curtime;

    debugs(20, 2, "need " << pagesRequired << " pages");

    // let abandon()/handleIdleEntry() know about the impeding memory shortage
    memoryPagesDebt_ = pagesRequired;

    // XXX: SMP-unaware: Walkers should iterate memory cache, not store_table.
    // XXX: Limit iterations by time, not arbitrary count.
    const auto walker = mem_policy->PurgeInit(mem_policy, 100000);
    int removed = 0;
    while (const auto entry = walker->Next(walker)) {
        // Abandoned memory cache entries are purged during memory shortage.
        entry->abandon(__FUNCTION__); // may delete entry
        ++removed;

        if (memoryCacheHasSpaceFor(pagesRequired))
            break;
    }
    // TODO: Move to RemovalPolicyWalker::Done() that has more/better details.
    debugs(20, 3, "removed " << removed << " out of " << hot_obj_count  << " memory-cached entries");
    walker->Done(walker);
    memoryPagesDebt_ = 0;
}

// move this into [non-shared] memory cache class when we have one
/// whether e should be kept in local RAM for possible future caching
bool
Store::Controller::keepForLocalMemoryCache(StoreEntry &e) const
{
    if (!e.memoryCachable())
        return false;

    // does the current and expected size obey memory caching limits?
    assert(e.mem_obj);
    const int64_t loadedSize = e.mem_obj->endOffset();
    const int64_t expectedSize = e.mem_obj->expectedReplySize(); // may be < 0
    const int64_t ramSize = max(loadedSize, expectedSize);
    const int64_t ramLimit = min(
                                 static_cast<int64_t>(Config.memMaxSize),
                                 static_cast<int64_t>(Config.Store.maxInMemObjSize));
    return ramSize <= ramLimit;
}

void
Store::Controller::memoryOut(StoreEntry &e, const bool preserveSwappable)
{
    bool keepInLocalMemory = false;
    if (sharedMemStore)
        sharedMemStore->write(e); // leave keepInLocalMemory false
    else if (localMemStore)
        keepInLocalMemory = keepForLocalMemoryCache(e);

    debugs(20, 7, HERE << "keepInLocalMemory: " << keepInLocalMemory);

    if (!keepInLocalMemory)
        e.trimMemory(preserveSwappable);
}

/// removes the entry from the memory cache
/// XXX: Dangerous side effect: Unlocked entries lose their mem_obj.
void
Store::Controller::memoryEvictCached(StoreEntry &e)
{
    // TODO: Untangle memory caching from mem_obj.
    if (sharedMemStore)
        sharedMemStore->evictCached(e);
    else // TODO: move into [non-shared] memory cache class when we have one
        if (!e.locked())
            e.destroyMemObject();
}

void
Store::Controller::memoryDisconnect(StoreEntry &e)
{
    if (sharedMemStore)
        sharedMemStore->disconnect(e);
    // else nothing to do for non-shared memory cache
}

void
Store::Controller::stopSharing(StoreEntry &e)
{
    // Marking the transients entry is sufficient to prevent new readers from
    // starting to wait for `e` updates and to inform the current readers (and,
    // hence, Broadcast() recipients) about the underlying Store problems.
    if (transients && e.hasTransients())
        transients->evictCached(e);
}

void
Store::Controller::transientsCompleteWriting(StoreEntry &e)
{
    // transients->isWriter(e) is false if `e` is writing to its second store
    // after finishing writing to its first store: At the end of the first swap
    // out, the transients writer becomes a reader and (XXX) we never switch
    // back to writing, even if we start swapping out again (to another store).
    if (transients && e.hasTransients() && transients->isWriter(e))
        transients->completeWriting(e);
}

int
Store::Controller::transientReaders(const StoreEntry &e) const
{
    return (transients && e.hasTransients()) ?
           transients->readers(e) : 0;
}

void
Store::Controller::transientsDisconnect(StoreEntry &e)
{
    if (transients)
        transients->disconnect(e);
}

void
Store::Controller::transientsClearCollapsingRequirement(StoreEntry &e)
{
    if (transients)
        transients->clearCollapsingRequirement(e);
}

void
Store::Controller::handleIdleEntry(StoreEntry &e)
{
    bool keepInLocalMemory = false;

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL)) {
        // Icons (and cache digests?) should stay in store_table until we
        // have a dedicated storage for them (that would not purge them).
        // They are not managed [well] by any specific Store handled below.
        keepInLocalMemory = true;
    } else if (sharedMemStore) {
        // leave keepInLocalMemory false; sharedMemStore maintains its own cache
    } else if (localMemStore) {
        keepInLocalMemory = keepForLocalMemoryCache(e) && // in good shape and
                            // the local memory cache is not overflowing
                            memoryCacheHasSpaceFor(memoryPagesDebt_);
    }

    // An idle, unlocked entry that only belongs to a SwapDir which controls
    // its own index, should not stay in the global store_table.
    if (!dereferenceIdle(e, keepInLocalMemory)) {
        debugs(20, 5, HERE << "destroying unlocked entry: " << &e << ' ' << e);
        destroyStoreEntry(static_cast<hash_link*>(&e));
        return;
    }

    debugs(20, 5, HERE << "keepInLocalMemory: " << keepInLocalMemory);

    // TODO: move this into [non-shared] memory cache class when we have one
    if (keepInLocalMemory) {
        e.setMemStatus(IN_MEMORY);
        e.mem_obj->unlinkRequest();
        return;
    }

    // We know the in-memory data will be gone. Get rid of the entire entry if
    // it has nothing worth preserving on disk either.
    if (!e.swappedOut()) {
        e.release(); // deletes e
        return;
    }

    memoryEvictCached(e); // may already be gone
    // and keep the entry in store_table for its on-disk data
}

void
Store::Controller::updateOnNotModified(StoreEntry *old, StoreEntry &e304)
{
    Must(old);
    Must(old->mem_obj);
    Must(e304.mem_obj);

    // updateOnNotModified() may be called many times for the same old entry.
    // e304.mem_obj->appliedUpdates value distinguishes two cases:
    //   false: Independent store clients revalidating the same old StoreEntry.
    //          Each such update uses its own e304. The old StoreEntry
    //          accumulates such independent updates.
    //   true: Store clients feeding off the same 304 response. Each such update
    //         uses the same e304. For timestamps correctness and performance
    //         sake, it is best to detect and skip such repeated update calls.
    if (e304.mem_obj->appliedUpdates) {
        debugs(20, 5, "ignored repeated update of " << *old << " with " << e304);
        return;
    }
    e304.mem_obj->appliedUpdates = true;

    if (!old->updateOnNotModified(e304)) {
        debugs(20, 5, "updated nothing in " << *old << " with " << e304);
        return;
    }

    if (sharedMemStore && old->mem_status == IN_MEMORY && !EBIT_TEST(old->flags, ENTRY_SPECIAL))
        sharedMemStore->updateHeaders(old);

    if (old->swap_dirn > -1)
        swapDir->updateHeaders(old);
}

bool
Store::Controller::allowCollapsing(StoreEntry *e, const RequestFlags &reqFlags,
                                   const HttpRequestMethod &reqMethod)
{
    const KeyScope keyScope = reqFlags.refresh ? ksRevalidation : ksDefault;
    // set the flag now so that it gets copied into the Transients entry
    e->setCollapsingRequirement(true);
    if (e->makePublic(keyScope)) { // this is needed for both local and SMP collapsing
        debugs(20, 3, "may " << (transients && e->hasTransients() ?
                                 "SMP-" : "locally-") << "collapse " << *e);
        return true;
    }
    // paranoid cleanup; the flag is meaningless for private entries
    e->setCollapsingRequirement(false);
    return false;
}

void
Store::Controller::addReading(StoreEntry *e, const cache_key *key)
{
    if (transients)
        transients->monitorIo(e, key, Store::ioReading);
    e->hashInsert(key);
}

void
Store::Controller::addWriting(StoreEntry *e, const cache_key *key)
{
    assert(e);
    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
        return; // constant memory-resident entries do not need transients

    if (transients)
        transients->monitorIo(e, key, Store::ioWriting);
    // else: non-SMP configurations do not need transients
}

void
Store::Controller::syncCollapsed(const sfileno xitIndex)
{
    assert(transients);

    StoreEntry *collapsed = transients->findCollapsed(xitIndex);
    if (!collapsed) { // the entry is no longer active, ignore update
        debugs(20, 7, "not SMP-syncing not-transient " << xitIndex);
        return;
    }

    if (!collapsed->locked()) {
        debugs(20, 3, "skipping (and may destroy) unlocked " << *collapsed);
        handleIdleEntry(*collapsed);
        return;
    }

    assert(collapsed->mem_obj);

    if (EBIT_TEST(collapsed->flags, ENTRY_ABORTED)) {
        debugs(20, 3, "skipping already aborted " << *collapsed);
        return;
    }

    debugs(20, 7, "syncing " << *collapsed);

    Transients::EntryStatus entryStatus;
    transients->status(*collapsed, entryStatus);

    if (!entryStatus.collapsed) {
        debugs(20, 5, "removing collapsing requirement for " << *collapsed << " since remote writer probably got headers");
        collapsed->setCollapsingRequirement(false);
    }

    if (entryStatus.waitingToBeFreed) {
        debugs(20, 3, "will release " << *collapsed << " due to waitingToBeFreed");
        collapsed->release(true); // may already be marked
    }

    if (transients->isWriter(*collapsed))
        return; // readers can only change our waitingToBeFreed flag

    assert(transients->isReader(*collapsed));

    if (entryStatus.abortedByWriter) {
        debugs(20, 3, "aborting " << *collapsed << " because its writer has aborted");
        collapsed->abort();
        return;
    }

    if (entryStatus.collapsed && !collapsed->hittingRequiresCollapsing()) {
        debugs(20, 3, "aborting " << *collapsed << " due to writer/reader collapsing state mismatch");
        collapsed->abort();
        return;
    }

    bool found = false;
    bool inSync = false;
    if (sharedMemStore && collapsed->mem_obj->memCache.io == MemObject::ioDone) {
        found = true;
        inSync = true;
        debugs(20, 7, "fully mem-loaded " << *collapsed);
    } else if (sharedMemStore && collapsed->hasMemStore()) {
        found = true;
        inSync = sharedMemStore->updateAnchored(*collapsed);
        // TODO: handle entries attached to both memory and disk
    } else if (swapDir && collapsed->hasDisk()) {
        found = true;
        inSync = swapDir->updateAnchored(*collapsed);
    } else {
        found = anchorToCache(*collapsed, inSync);
    }

    if (entryStatus.waitingToBeFreed && !found) {
        debugs(20, 3, "aborting unattached " << *collapsed <<
               " because it was marked for deletion before we could attach it");
        collapsed->abort();
        return;
    }

    if (inSync) {
        debugs(20, 5, "synced " << *collapsed);
        collapsed->invokeHandlers();
        return;
    }

    if (found) { // unrecoverable problem syncing this entry
        debugs(20, 3, "aborting unsyncable " << *collapsed);
        collapsed->abort();
        return;
    }

    // the entry is still not in one of the caches
    debugs(20, 7, "waiting " << *collapsed);
}

/// Called for Transients entries that are not yet anchored to a cache.
/// For cached entries, return true after synchronizing them with their cache
/// (making inSync true on success). For not-yet-cached entries, return false.
bool
Store::Controller::anchorToCache(StoreEntry &entry, bool &inSync)
{
    assert(entry.hasTransients());
    assert(transientsReader(entry));

    debugs(20, 7, "anchoring " << entry);

    bool found = false;
    if (sharedMemStore)
        found = sharedMemStore->anchorToCache(entry, inSync);
    if (!found && swapDir)
        found = swapDir->anchorToCache(entry, inSync);

    if (found) {
        if (inSync)
            debugs(20, 7, "anchored " << entry);
        else
            debugs(20, 5, "failed to anchor " << entry);
    } else {
        debugs(20, 7, "skipping not yet cached " << entry);
    }

    return found;
}

bool
Store::Controller::SmpAware()
{
    return MemStore::Enabled() || Disks::SmpAware();
}

void
Store::Controller::checkTransients(const StoreEntry &e) const
{
    if (EBIT_TEST(e.flags, ENTRY_SPECIAL))
        return;
    assert(!transients || e.hasTransients());
}

namespace Store {
static RefCount<Controller> TheRoot;
}

Store::Controller&
Store::Root()
{
    assert(TheRoot);
    return *TheRoot;
}

void
Store::Init(Controller *root)
{
    TheRoot = root ? root : new Controller;
}

void
Store::FreeMemory()
{
    TheRoot = nullptr;
}

