/*
 * DEBUG: section 20    Memory Cache
 *
 */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "HttpReply.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/Pages.h"
#include "MemObject.h"
#include "MemStore.h"
#include "mime_header.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "StoreStats.h"
#include "tools.h"

/// shared memory segment path to use for MemStore maps
static const char *MapLabel = "cache_mem_map";
/// shared memory segment path to use for the free slices index
static const char *SpaceLabel = "cache_mem_space";
// TODO: sync with Rock::SwapDir::*Path()

// We store free slot IDs (i.e., "space") as Page objects so that we can use
// Ipc::Mem::PageStack. Pages require pool IDs. The value here is not really
// used except for a positivity test. A unique value is handy for debugging.
static const uint32_t SpacePoolId = 510716;


MemStore::MemStore(): map(NULL), lastWritingSlice(-1)
{
}

MemStore::~MemStore()
{
    delete map;
}

void
MemStore::init()
{
    const int64_t entryLimit = EntryLimit();
    if (entryLimit <= 0)
        return; // no memory cache configured or a misconfiguration

    // check compatibility with the disk cache, if any
    if (Config.cacheSwap.n_configured > 0) {
    const int64_t diskMaxSize = Store::Root().maxObjectSize();
    const int64_t memMaxSize = maxObjectSize();
    if (diskMaxSize == -1) {
        debugs(20, DBG_IMPORTANT, "WARNING: disk-cache maximum object size "
               "is unlimited but mem-cache maximum object size is " <<
               memMaxSize / 1024.0 << " KB");
    } else if (diskMaxSize > memMaxSize) {
        debugs(20, DBG_IMPORTANT, "WARNING: disk-cache maximum object size "
               "is too large for mem-cache: " <<
               diskMaxSize / 1024.0 << " KB > " <<
               memMaxSize / 1024.0 << " KB");
    }
    }

    freeSlots = shm_old(Ipc::Mem::PageStack)(SpaceLabel);

    Must(!map);
    map = new MemStoreMap(MapLabel);
    map->cleaner = this;
}

void
MemStore::getStats(StoreInfoStats &stats) const
{
    const size_t pageSize = Ipc::Mem::PageSize();

    stats.mem.shared = true;
    stats.mem.capacity =
        Ipc::Mem::PageLimit(Ipc::Mem::PageId::cachePage) * pageSize;
    stats.mem.size =
        Ipc::Mem::PageLevel(Ipc::Mem::PageId::cachePage) * pageSize;
    stats.mem.count = currentCount();
}

void
MemStore::stat(StoreEntry &e) const
{
    storeAppendPrintf(&e, "\n\nShared Memory Cache\n");

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

            const unsigned int slotsFree =
                Ipc::Mem::PagesAvailable(Ipc::Mem::PageId::cachePage);
            if (slotsFree <= static_cast<const unsigned int>(limit)) {
                const int usedSlots = limit - static_cast<const int>(slotsFree);
                storeAppendPrintf(&e, "Used slots:      %9d %.2f%%\n",
                                  usedSlots, (100.0 * usedSlots / limit));
            }

            if (limit < 100) { // XXX: otherwise too expensive to count
                Ipc::ReadWriteLockStats stats;
                map->updateStats(stats);
                stats.dump(e);
            }
        }
    }
}

void
MemStore::maintain()
{
}

uint64_t
MemStore::minSize() const
{
    return 0; // XXX: irrelevant, but Store parent forces us to implement this
}

uint64_t
MemStore::maxSize() const
{
    return Config.memMaxSize;
}

uint64_t
MemStore::currentSize() const
{
    return Ipc::Mem::PageLevel(Ipc::Mem::PageId::cachePage) *
        Ipc::Mem::PageSize();
}

uint64_t
MemStore::currentCount() const
{
    return map ? map->entryCount() : 0;
}

int64_t
MemStore::maxObjectSize() const
{
    return min(Config.Store.maxInMemObjSize, Config.memMaxSize);
}

void
MemStore::reference(StoreEntry &)
{
}

bool
MemStore::dereference(StoreEntry &, bool)
{
    // no need to keep e in the global store_table for us; we have our own map
    return false;
}

int
MemStore::callback()
{
    return 0;
}

StoreSearch *
MemStore::search(String const, HttpRequest *)
{
    fatal("not implemented");
    return NULL;
}

StoreEntry *
MemStore::get(const cache_key *key)
{
    if (!map)
        return NULL;

    sfileno index;
    const Ipc::StoreMapAnchor *const slot = map->openForReading(key, index);
    if (!slot)
        return NULL;

    const Ipc::StoreMapAnchor::Basics &basics = slot->basics;

    // create a brand new store entry and initialize it with stored info
    StoreEntry *e = new StoreEntry();
    e->lock_count = 0;

    e->swap_file_sz = basics.swap_file_sz;
    e->lastref = basics.lastref;
    e->timestamp = basics.timestamp;
    e->expires = basics.expires;
    e->lastmod = basics.lastmod;
    e->refcount = basics.refcount;
    e->flags = basics.flags;

    e->store_status = STORE_OK;
    e->mem_status = IN_MEMORY; // setMemStatus(IN_MEMORY) requires mem_obj
    //e->swap_status = set in StoreEntry constructor to SWAPOUT_NONE;
    e->ping_status = PING_NONE;

    EBIT_SET(e->flags, ENTRY_CACHABLE);
    EBIT_CLR(e->flags, RELEASE_REQUEST);
    EBIT_CLR(e->flags, KEY_PRIVATE);
    EBIT_SET(e->flags, ENTRY_VALIDATED);

    const bool copied = copyFromShm(*e, index, *slot);

    // we copied everything we could to local memory; no more need to lock
    map->closeForReading(index);

    if (copied) {
        e->hashInsert(key);
        return e;
    }

    debugs(20, 3, HERE << "mem-loading failed; freeing " << index);
    map->freeEntry(index); // do not let others into the same trap
    return NULL;
}

void
MemStore::get(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    // XXX: not needed but Store parent forces us to implement this
    fatal("MemStore::get(key,callback,data) should not be called");
}

/// copies the entire entry from shared to local memory
bool
MemStore::copyFromShm(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor)
{
    debugs(20, 7, "mem-loading entry " << index << " from " << anchor.start);

    // XXX: We do not know the URLs yet, only the key, but we need to parse and
    // store the response for the Root().get() callers to be happy because they
    // expect IN_MEMORY entries to already have the response headers and body.
    // At least one caller calls createMemObject() if there is not one, so
    // we hide the true object until that happens (to avoid leaking TBD URLs).
    e.createMemObject("TBD", "TBD");

    // emulate the usual Store code but w/o inapplicable checks and callbacks:

    Ipc::StoreMapSliceId sid = anchor.start;
    int64_t offset = 0;
    while (sid >= 0) {
        const Ipc::StoreMapSlice &slice = map->readableSlice(index, sid);
        const MemStoreMap::Extras &extras = map->extras(sid);
        StoreIOBuffer sliceBuf(slice.size, offset,
                               static_cast<char*>(PagePointer(extras.page)));
        if (!copyFromShmSlice(e, sliceBuf, slice.next < 0))
            return false;
        debugs(20, 9, "entry " << index << " slice " << sid << " filled " <<
               extras.page);
        offset += slice.size;
        sid = slice.next;
    }

    e.mem_obj->object_sz = e.mem_obj->endOffset(); // from StoreEntry::complete()
    debugs(20, 7, "mem-loaded all " << e.mem_obj->object_sz << '/' <<
           anchor.basics.swap_file_sz << " bytes of " << e);
    assert(e.mem_obj->object_sz >= 0);
    assert(static_cast<uint64_t>(e.mem_obj->object_sz) == anchor.basics.swap_file_sz);
    // would be nice to call validLength() here, but it needs e.key


    e.hideMemObject();

    return true;
}

/// imports one shared memory slice into local memory
bool
MemStore::copyFromShmSlice(StoreEntry &e, StoreIOBuffer &buf, bool eof)
{
    debugs(20, 7, "buf: " << buf.offset << " + " << buf.length);

    // from store_client::readBody()
    // parse headers if needed; they might span multiple slices!
    HttpReply *rep = (HttpReply *)e.getReply();
    if (rep->pstate < psParsed) {
        // XXX: have to copy because httpMsgParseStep() requires 0-termination
        MemBuf mb;
        mb.init(buf.length+1, buf.length+1);
        mb.append(buf.data, buf.length);        
        mb.terminate();
        const int result = rep->httpMsgParseStep(mb.buf, buf.length, eof);
        if (result > 0) {
            assert(rep->pstate == psParsed);
        } else if (result < 0) {
            debugs(20, DBG_IMPORTANT, "Corrupted mem-cached headers: " << e);
            return false;
        } else { // more slices are needed
            assert(!eof);
        }
    }
    debugs(20, 7, "rep pstate: " << rep->pstate);

    // local memory stores both headers and body so copy regardless of pstate
    const int64_t offBefore = e.mem_obj->endOffset();
    assert(e.mem_obj->data_hdr.write(buf)); // from MemObject::write()
    const int64_t offAfter = e.mem_obj->endOffset();
    // expect to write the entire buf because StoreEntry::write() never fails
    assert(offAfter >= 0 && offBefore <= offAfter &&
           static_cast<size_t>(offAfter - offBefore) == buf.length);
    return true;
}

bool
MemStore::keepInLocalMemory(const StoreEntry &e) const
{
    if (!e.memoryCachable()) {
        debugs(20, 7, HERE << "Not memory cachable: " << e);
        return false; // will not cache due to entry state or properties
    }

    assert(e.mem_obj);
    const int64_t loadedSize = e.mem_obj->endOffset();
    const int64_t expectedSize = e.mem_obj->expectedReplySize(); // may be < 0
    const int64_t ramSize = max(loadedSize, expectedSize);

    if (ramSize > maxObjectSize()) {
        debugs(20, 5, HERE << "Too big max(" <<
               loadedSize << ", " << expectedSize << "): " << e);
        return false; // will not cache due to cachable entry size limits
    }

    return true;
}

void
MemStore::considerKeeping(StoreEntry &e)
{
    if (!keepInLocalMemory(e))
        return;

    // since we copy everything at once, we can only keep complete entries
    if (e.store_status != STORE_OK) {
        debugs(20, 7, HERE << "Incomplete: " << e);
        return;
    }

    if (e.mem_status == IN_MEMORY) {
        debugs(20, 5, "already mem-cached: " << e);
        return;
    }

    assert(e.mem_obj);

    const int64_t loadedSize = e.mem_obj->endOffset();
    const int64_t expectedSize = e.mem_obj->expectedReplySize();

    // objects of unknown size are not allowed into memory cache, for now
    if (expectedSize < 0) {
        debugs(20, 5, HERE << "Unknown expected size: " << e);
        return;
    }

    // since we copy everything at once, we can only keep fully loaded entries
    if (loadedSize != expectedSize) {
        debugs(20, 7, HERE << "partially loaded: " << loadedSize << " != " <<
               expectedSize);
        return;
    }

    keep(e); // may still fail
}

/// locks map anchor and calls copyToShm to store the entry in shared memory
void
MemStore::keep(StoreEntry &e)
{
    if (!map) {
        debugs(20, 5, HERE << "No map to mem-cache " << e);
        return;
    }

    sfileno index = 0;
    Ipc::StoreMapAnchor *slot = map->openForWriting(reinterpret_cast<const cache_key *>(e.key), index);
    if (!slot) {
        debugs(20, 5, HERE << "No room in mem-cache map to index " << e);
        return;
    }

    try {
        if (copyToShm(e, index, *slot)) {
            slot->set(e);
            map->closeForWriting(index, false);
            return;
        }
        // fall through to the error handling code
    } 
    catch (const std::exception &x) { // TODO: should we catch ... as well?
        debugs(20, 2, "mem-caching error writing entry " << index <<
               ' ' << e << ": " << x.what());
        // fall through to the error handling code
    }

    map->abortIo(index);
}

/// copies all local data to shared memory
bool
MemStore::copyToShm(StoreEntry &e, const sfileno index, Ipc::StoreMapAnchor &anchor)
{
    const int64_t eSize = e.mem_obj->endOffset();
    int64_t offset = 0;
    lastWritingSlice = -1;
    while (offset < eSize) {
        if (!copyToShmSlice(e, index, anchor, offset))
            return false;
    }

    // check that we kept everything or purge incomplete/sparse cached entry
    if (eSize != offset) {
        debugs(20, 2, "Failed to mem-cache " << e << ": " <<
               eSize << " != " << offset);
        return false;
    }

    debugs(20, 7, "mem-cached all " << eSize << " bytes of " << e);
    e.swap_file_sz = eSize;

    return true;
}

/// copies one slice worth of local memory to shared memory
bool
MemStore::copyToShmSlice(StoreEntry &e, const sfileno index, Ipc::StoreMapAnchor &anchor, int64_t &offset)
{
    Ipc::Mem::PageId page;
    Ipc::StoreMapSliceId sid = reserveSapForWriting(page); // throws
    assert(sid >= 0 && page);
    map->extras(sid).page = page; // remember the page location for cleanup
    debugs(20, 7, "entry " << index << " slice " << sid << " has " << page);

    // link this slice with other entry slices to form a store entry chain
    if (!offset) {
        assert(lastWritingSlice < 0);
        anchor.start = sid;
        debugs(20, 7, "entry " << index << " starts at slice " << sid);
    } else {
        assert(lastWritingSlice >= 0);
        map->writeableSlice(index, lastWritingSlice).next = sid;
        debugs(20, 7, "entry " << index << " slice " << lastWritingSlice <<
               " followed by slice " << sid);
    }
    lastWritingSlice = sid;

    const int64_t bufSize = Ipc::Mem::PageSize();
    StoreIOBuffer sharedSpace(bufSize, offset,
                              static_cast<char*>(PagePointer(page)));

    // check that we kept everything or purge incomplete/sparse cached entry
    const ssize_t copied = e.mem_obj->data_hdr.copy(sharedSpace);
    if (copied <= 0) {
        debugs(20, 2, "Failed to mem-cache " << e << " using " <<
               bufSize << " bytes from " << offset << " in " << page);
        return false;
    }

    debugs(20, 7, "mem-cached " << copied << " bytes of " << e <<
           " from " << offset << " to " << page);

    Ipc::StoreMapSlice &slice = map->writeableSlice(index, sid);
    slice.next = -1;
    slice.size = copied;

    offset += copied;
    return true;
}

/// finds a slot and a free page to fill or throws
sfileno
MemStore::reserveSapForWriting(Ipc::Mem::PageId &page)
{
    Ipc::Mem::PageId slot;
    if (freeSlots->pop(slot)) {
        debugs(20, 5, "got a previously free slot: " << slot);

        if (Ipc::Mem::GetPage(Ipc::Mem::PageId::cachePage, page)) {
            debugs(20, 5, "and got a previously free page: " << page);
            return slot.number - 1;
        } else {
            debugs(20, 3, "but there is no free page, returning " << slot);
            freeSlots->push(slot);
        }
    }
        
    // catch free slots delivered to noteFreeMapSlice()
    assert(!waitingFor);
    waitingFor.slot = &slot;
    waitingFor.page = &page;
    if (map->purgeOne()) {
        assert(!waitingFor); // noteFreeMapSlice() should have cleared it
        assert(slot.set());
        assert(page.set());
        debugs(20, 5, "got previously busy " << slot << " and " << page);
        return slot.number - 1;
    }
    assert(waitingFor.slot == &slot && waitingFor.page == &page);
    waitingFor.slot = NULL;
    waitingFor.page = NULL;

    debugs(47, 3, "cannot get a slice; entries: " << map->entryCount());
    throw TexcHere("ran out of mem-cache slots");
}

void
MemStore::noteFreeMapSlice(const sfileno sliceId)
{
    Ipc::Mem::PageId &pageId = map->extras(sliceId).page;
    debugs(20, 9, "slice " << sliceId << " freed " << pageId);
    assert(pageId);
    Ipc::Mem::PageId slotId;
    slotId.pool = SpacePoolId;
    slotId.number = sliceId + 1;
    if (!waitingFor) {
        // must zero pageId before we give slice (and pageId extras!) to others
        Ipc::Mem::PutPage(pageId);
        freeSlots->push(slotId);
    } else {
        *waitingFor.slot = slotId;
        *waitingFor.page = pageId;
        waitingFor.slot = NULL;
        waitingFor.page = NULL;
        pageId = Ipc::Mem::PageId();
    }
}

/// calculates maximum number of entries we need to store and map
int64_t
MemStore::EntryLimit()
{
    if (!Config.memShared || !Config.memMaxSize)
        return 0; // no memory cache configured

    const int64_t minEntrySize = Ipc::Mem::PageSize();
    const int64_t entryLimit = Config.memMaxSize / minEntrySize;
    return entryLimit;
}

/// reports our needs for shared memory pages to Ipc::Mem::Pages
class MemStoreClaimMemoryNeedsRr: public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void run(const RunnerRegistry &r);
};

RunnerRegistrationEntry(rrClaimMemoryNeeds, MemStoreClaimMemoryNeedsRr);

void
MemStoreClaimMemoryNeedsRr::run(const RunnerRegistry &)
{
    Ipc::Mem::NotePageNeed(Ipc::Mem::PageId::cachePage, MemStore::EntryLimit());
}

/// decides whether to use a shared memory cache or checks its configuration
class MemStoreCfgRr: public ::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void run(const RunnerRegistry &);
};

RunnerRegistrationEntry(rrFinalizeConfig, MemStoreCfgRr);

void MemStoreCfgRr::run(const RunnerRegistry &r)
{
    // decide whether to use a shared memory cache if the user did not specify
    if (!Config.memShared.configured()) {
        Config.memShared.configure(Ipc::Atomic::Enabled() &&
                                   Ipc::Mem::Segment::Enabled() && UsingSmp() &&
                                   Config.memMaxSize > 0);
    } else if (Config.memShared && !Ipc::Atomic::Enabled()) {
        // bail if the user wants shared memory cache but we cannot support it
        fatal("memory_cache_shared is on, but no support for atomic operations detected");
    } else if (Config.memShared && !Ipc::Mem::Segment::Enabled()) {
        fatal("memory_cache_shared is on, but no support for shared memory detected");
    } else if (Config.memShared && !UsingSmp()) {
        debugs(20, DBG_IMPORTANT, "WARNING: memory_cache_shared is on, but only"
               " a single worker is running");
    }
}

/// initializes shared memory segments used by MemStore
class MemStoreRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    MemStoreRr(): spaceOwner(NULL), mapOwner(NULL) {}
    virtual void run(const RunnerRegistry &);
    virtual ~MemStoreRr();

protected:
    virtual void create(const RunnerRegistry &);

private:
    Ipc::Mem::Owner<Ipc::Mem::PageStack> *spaceOwner; ///< free slices Owner
    MemStoreMap::Owner *mapOwner; ///< primary map Owner
};

RunnerRegistrationEntry(rrAfterConfig, MemStoreRr);

void MemStoreRr::run(const RunnerRegistry &r)
{
    assert(Config.memShared.configured());
    Ipc::Mem::RegisteredRunner::run(r);
}

void MemStoreRr::create(const RunnerRegistry &)
{
    if (!Config.memShared)
        return;

    const int64_t entryLimit = MemStore::EntryLimit();
    if (entryLimit <= 0) {
        if (Config.memMaxSize > 0) {
            debugs(20, DBG_IMPORTANT, "WARNING: mem-cache size is too small ("
                   << (Config.memMaxSize / 1024.0) << " KB), should be >= " <<
                   (Ipc::Mem::PageSize() / 1024.0) << " KB");
        }
        return; // no memory cache configured or a misconfiguration
    }

    Must(!spaceOwner);
    spaceOwner = shm_new(Ipc::Mem::PageStack)(SpaceLabel, SpacePoolId,
                                              entryLimit,
                                              sizeof(Ipc::Mem::PageId));
    Must(!mapOwner);
    mapOwner = MemStoreMap::Init(MapLabel, entryLimit);
}

MemStoreRr::~MemStoreRr()
{
    delete mapOwner;
    delete spaceOwner;
}
