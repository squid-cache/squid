/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Memory Cache */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "CollapsedForwarding.h"
#include "HttpReply.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/Pages.h"
#include "MemObject.h"
#include "MemStore.h"
#include "mime_header.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "store/forward.h"
#include "StoreStats.h"
#include "tools.h"

/// shared memory segment path to use for MemStore maps
static const auto MapLabel = "cache_mem_map";
/// shared memory segment path to use for the free slices index
static const char *SpaceLabel = "cache_mem_space";
/// shared memory segment path to use for IDs of shared pages with slice data
static const char *ExtrasLabel = "cache_mem_ex";
// TODO: sync with Rock::SwapDir::*Path()

/// Packs to shared memory, allocating new slots/pages as needed.
/// Requires an Ipc::StoreMapAnchor locked for writing.
class ShmWriter: public Packable
{
public:
    ShmWriter(MemStore &aStore, StoreEntry *anEntry, const sfileno aFileNo, Ipc::StoreMapSliceId aFirstSlice = -1);

    /* Packable API */
    void append(const char *aBuf, int aSize) override;
    void vappendf(const char *fmt, va_list ap) override;

public:
    StoreEntry *entry; ///< the entry being updated

    /// the slot keeping the first byte of the appended content (at least)
    /// either set via constructor parameter or allocated by the first append
    Ipc::StoreMapSliceId firstSlice;

    /// the slot keeping the last byte of the appended content (at least)
    Ipc::StoreMapSliceId lastSlice;

    uint64_t totalWritten; ///< cumulative number of bytes appended so far

protected:
    void copyToShm();
    void copyToShmSlice(Ipc::StoreMap::Slice &slice);

private:
    MemStore &store;
    const sfileno fileNo;

    /* set by (and only valid during) append calls */
    const char *buf; ///< content being appended now
    int bufSize; ///< buf size
    int bufWritten; ///< buf bytes appended so far
};

/* ShmWriter */

ShmWriter::ShmWriter(MemStore &aStore, StoreEntry *anEntry, const sfileno aFileNo, Ipc::StoreMapSliceId aFirstSlice):
    entry(anEntry),
    firstSlice(aFirstSlice),
    lastSlice(firstSlice),
    totalWritten(0),
    store(aStore),
    fileNo(aFileNo),
    buf(nullptr),
    bufSize(0),
    bufWritten(0)
{
    Must(entry);
}

void
ShmWriter::append(const char *aBuf, int aBufSize)
{
    Must(!buf);
    buf = aBuf;
    bufSize = aBufSize;
    if (bufSize) {
        Must(buf);
        bufWritten = 0;
        copyToShm();
    }
    buf = nullptr;
    bufSize = 0;
    bufWritten = 0;
}

void
ShmWriter::vappendf(const char *fmt, va_list ap)
{
    SBuf vaBuf;
    va_list apCopy;
    va_copy(apCopy, ap);
    vaBuf.vappendf(fmt, apCopy);
    va_end(apCopy);
    append(vaBuf.rawContent(), vaBuf.length());
}

/// copies the entire buffer to shared memory
void
ShmWriter::copyToShm()
{
    Must(bufSize > 0); // do not use up shared memory pages for nothing
    Must(firstSlice < 0 || lastSlice >= 0);

    // fill, skip slices that are already full
    while (bufWritten < bufSize) {
        Ipc::StoreMap::Slice &slice = store.nextAppendableSlice(fileNo, lastSlice);
        if (firstSlice < 0)
            firstSlice = lastSlice;
        copyToShmSlice(slice);
    }

    debugs(20, 7, "stored " << bufWritten << '/' << totalWritten << " header bytes of " << *entry);
}

/// copies at most one slice worth of buffer to shared memory
void
ShmWriter::copyToShmSlice(Ipc::StoreMap::Slice &slice)
{
    Ipc::Mem::PageId page = store.pageForSlice(lastSlice);
    debugs(20, 7, "entry " << *entry << " slice " << lastSlice << " has " <<
           page);

    Must(bufWritten <= bufSize);
    const int64_t writingDebt = bufSize - bufWritten;
    const int64_t pageSize = Ipc::Mem::PageSize();
    const int64_t sliceOffset = totalWritten % pageSize;
    const int64_t copySize = std::min(writingDebt, pageSize - sliceOffset);
    memcpy(static_cast<char*>(PagePointer(page)) + sliceOffset, buf + bufWritten,
           copySize);

    debugs(20, 7, "copied " << slice.size << '+' << copySize << " bytes of " <<
           entry << " from " << sliceOffset << " in " << page);

    slice.size += copySize;
    bufWritten += copySize;
    totalWritten += copySize;
    // fresh anchor.basics.swap_file_sz is already set [to the stale value]

    // either we wrote everything or we filled the entire slice
    Must(bufWritten == bufSize || sliceOffset + copySize == pageSize);
}

/* MemStore */

MemStore::MemStore(): map(nullptr), lastWritingSlice(-1)
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
        return; // no shared memory cache configured or a misconfiguration

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
    extras = shm_old(Extras)(ExtrasLabel);

    Must(!map);
    map = new MemStoreMap(SBuf(MapLabel));
    map->cleaner = this;
}

void
MemStore::getStats(StoreInfoStats &stats) const
{
    const size_t pageSize = Ipc::Mem::PageSize();

    stats.mem.shared = true;

    // In SMP mode, only the first worker reports shared memory stats to avoid
    // adding up same-cache positive stats (reported by multiple worker
    // processes) when Coordinator aggregates worker-reported stats.
    // See also: Store::Disk::doReportStat().
    if (UsingSmp() && KidIdentifier != 1)
        return;

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
        const int entryLimit = map->entryLimit();
        const int slotLimit = map->sliceLimit();
        storeAppendPrintf(&e, "Maximum entries: %9d\n", entryLimit);
        if (entryLimit > 0) {
            storeAppendPrintf(&e, "Current entries: %" PRId64 " %.2f%%\n",
                              currentCount(), (100.0 * currentCount() / entryLimit));
        }

        storeAppendPrintf(&e, "Maximum slots:   %9d\n", slotLimit);
        if (slotLimit > 0) {
            const unsigned int slotsFree =
                Ipc::Mem::PagesAvailable(Ipc::Mem::PageId::cachePage);
            if (slotsFree <= static_cast<unsigned int>(slotLimit)) {
                const int usedSlots = slotLimit - static_cast<int>(slotsFree);
                storeAppendPrintf(&e, "Used slots:      %9d %.2f%%\n",
                                  usedSlots, (100.0 * usedSlots / slotLimit));
            }

            if (slotLimit < 100) { // XXX: otherwise too expensive to count
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
MemStore::dereference(StoreEntry &)
{
    // no need to keep e in the global store_table for us; we have our own map
    return false;
}

StoreEntry *
MemStore::get(const cache_key *key)
{
    if (!map)
        return nullptr;

    sfileno index;
    const Ipc::StoreMapAnchor *const slot = map->openForReading(key, index);
    if (!slot)
        return nullptr;

    // create a brand new store entry and initialize it with stored info
    StoreEntry *e = new StoreEntry();

    try {
        // XXX: We do not know the URLs yet, only the key, but we need to parse and
        // store the response for the Root().find() callers to be happy because they
        // expect IN_MEMORY entries to already have the response headers and body.
        e->createMemObject();

        anchorEntry(*e, index, *slot);

        // TODO: make copyFromShm() throw on all failures, simplifying this code
        if (copyFromShm(*e, index, *slot))
            return e;
        debugs(20, 3, "failed for " << *e);
    } catch (...) {
        // see store_client::parseHttpHeadersFromDisk() for problems this may log
        debugs(20, DBG_IMPORTANT, "ERROR: Cannot load a cache hit from shared memory" <<
               Debug::Extra << "exception: " << CurrentException <<
               Debug::Extra << "cache_mem entry: " << *e);
    }

    map->freeEntry(index); // do not let others into the same trap
    destroyStoreEntry(static_cast<hash_link *>(e));
    return nullptr;
}

void
MemStore::updateHeaders(StoreEntry *updatedE)
{
    if (!map)
        return;

    Ipc::StoreMapUpdate update(updatedE);
    assert(updatedE);
    assert(updatedE->mem_obj);
    if (!map->openForUpdating(update, updatedE->mem_obj->memCache.index))
        return;

    try {
        updateHeadersOrThrow(update);
    } catch (const std::exception &ex) {
        debugs(20, 2, "error starting to update entry " << *updatedE << ": " << ex.what());
        map->abortUpdating(update);
    }
}

void
MemStore::updateHeadersOrThrow(Ipc::StoreMapUpdate &update)
{
    // our +/- hdr_sz math below does not work if the chains differ [in size]
    Must(update.stale.anchor->basics.swap_file_sz == update.fresh.anchor->basics.swap_file_sz);

    const uint64_t staleHdrSz = update.entry->mem().baseReply().hdr_sz;
    debugs(20, 7, "stale hdr_sz: " << staleHdrSz);

    /* we will need to copy same-slice payload after the stored headers later */
    Must(staleHdrSz > 0);
    update.stale.splicingPoint = map->sliceContaining(update.stale.fileNo, staleHdrSz);
    Must(update.stale.splicingPoint >= 0);
    Must(update.stale.anchor->basics.swap_file_sz >= staleHdrSz);

    Must(update.stale.anchor);
    ShmWriter writer(*this, update.entry, update.fresh.fileNo);
    update.entry->mem().freshestReply().packHeadersUsingSlowPacker(writer);
    const uint64_t freshHdrSz = writer.totalWritten;
    debugs(20, 7, "fresh hdr_sz: " << freshHdrSz << " diff: " << (freshHdrSz - staleHdrSz));

    /* copy same-slice payload remaining after the stored headers */
    const Ipc::StoreMapSlice &slice = map->readableSlice(update.stale.fileNo, update.stale.splicingPoint);
    const Ipc::StoreMapSlice::Size sliceCapacity = Ipc::Mem::PageSize();
    const Ipc::StoreMapSlice::Size headersInLastSlice = staleHdrSz % sliceCapacity;
    Must(headersInLastSlice > 0); // or sliceContaining() would have stopped earlier
    Must(slice.size >= headersInLastSlice);
    const Ipc::StoreMapSlice::Size payloadInLastSlice = slice.size - headersInLastSlice;
    const MemStoreMapExtras::Item &extra = extras->items[update.stale.splicingPoint];
    char *page = static_cast<char*>(PagePointer(extra.page));
    debugs(20, 5, "appending same-slice payload: " << payloadInLastSlice);
    writer.append(page + headersInLastSlice, payloadInLastSlice);
    update.fresh.splicingPoint = writer.lastSlice;

    update.fresh.anchor->basics.swap_file_sz -= staleHdrSz;
    update.fresh.anchor->basics.swap_file_sz += freshHdrSz;

    map->closeForUpdating(update);
}

bool
MemStore::anchorToCache(StoreEntry &entry)
{
    Assure(!entry.hasMemStore());
    Assure(entry.mem().memCache.io != Store::ioDone);

    if (!map)
        return false;

    sfileno index;
    const Ipc::StoreMapAnchor *const slot = map->openForReading(
            reinterpret_cast<cache_key*>(entry.key), index);
    if (!slot)
        return false;

    anchorEntry(entry, index, *slot);
    if (!updateAnchoredWith(entry, index, *slot))
        throw TextException("updateAnchoredWith() failure", Here());
    return true;
}

bool
MemStore::updateAnchored(StoreEntry &entry)
{
    if (!map)
        return false;

    assert(entry.mem_obj);
    assert(entry.hasMemStore());
    const sfileno index = entry.mem_obj->memCache.index;
    const Ipc::StoreMapAnchor &anchor = map->readableEntry(index);
    return updateAnchoredWith(entry, index, anchor);
}

/// updates Transients entry after its anchor has been located
bool
MemStore::updateAnchoredWith(StoreEntry &entry, const sfileno index, const Ipc::StoreMapAnchor &anchor)
{
    entry.swap_file_sz = anchor.basics.swap_file_sz;
    const bool copied = copyFromShm(entry, index, anchor);
    return copied;
}

/// anchors StoreEntry to an already locked map entry
void
MemStore::anchorEntry(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor)
{
    assert(!e.hasDisk()); // no conflict with disk entry basics
    anchor.exportInto(e);

    assert(e.mem_obj);
    if (anchor.complete()) {
        e.store_status = STORE_OK;
        e.mem_obj->object_sz = e.swap_file_sz;
        e.setMemStatus(IN_MEMORY);
    } else {
        e.store_status = STORE_PENDING;
        assert(e.mem_obj->object_sz < 0);
        e.setMemStatus(NOT_IN_MEMORY);
    }

    EBIT_SET(e.flags, ENTRY_VALIDATED);

    MemObject::MemCache &mc = e.mem_obj->memCache;
    mc.index = index;
    mc.io = Store::ioReading;
}

/// copies the entire entry from shared to local memory
bool
MemStore::copyFromShm(StoreEntry &e, const sfileno index, const Ipc::StoreMapAnchor &anchor)
{
    debugs(20, 7, "mem-loading entry " << index << " from " << anchor.start);
    assert(e.mem_obj);

    // emulate the usual Store code but w/o inapplicable checks and callbacks:

    Ipc::StoreMapSliceId sid = anchor.start; // optimize: remember the last sid
    bool wasEof = anchor.complete() && sid < 0;
    int64_t sliceOffset = 0;

    SBuf httpHeaderParsingBuffer;
    while (sid >= 0) {
        const Ipc::StoreMapSlice &slice = map->readableSlice(index, sid);
        // slice state may change during copying; take snapshots now
        wasEof = anchor.complete() && slice.next < 0;
        const Ipc::StoreMapSlice::Size wasSize = slice.size;

        debugs(20, 8, "entry " << index << " slice " << sid << " eof " <<
               wasEof << " wasSize " << wasSize << " <= " <<
               anchor.basics.swap_file_sz << " sliceOffset " << sliceOffset <<
               " mem.endOffset " << e.mem_obj->endOffset());

        if (e.mem_obj->endOffset() < sliceOffset + wasSize) {
            // size of the slice data that we already copied
            const size_t prefixSize = e.mem_obj->endOffset() - sliceOffset;
            assert(prefixSize <= wasSize);

            const MemStoreMapExtras::Item &extra = extras->items[sid];

            char *page = static_cast<char*>(PagePointer(extra.page));
            const StoreIOBuffer sliceBuf(wasSize - prefixSize,
                                         e.mem_obj->endOffset(),
                                         page + prefixSize);

            copyFromShmSlice(e, sliceBuf);
            debugs(20, 8, "entry " << index << " copied slice " << sid <<
                   " from " << extra.page << '+' << prefixSize);

            // parse headers if needed; they might span multiple slices!
            if (!e.hasParsedReplyHeader()) {
                httpHeaderParsingBuffer.append(sliceBuf.data, sliceBuf.length);
                auto &reply = e.mem().adjustableBaseReply();
                if (reply.parseTerminatedPrefix(httpHeaderParsingBuffer.c_str(), httpHeaderParsingBuffer.length()))
                    httpHeaderParsingBuffer = SBuf(); // we do not need these bytes anymore
            }
        }
        // else skip a [possibly incomplete] slice that we copied earlier

        // careful: the slice may have grown _and_ gotten the next slice ID!
        if (slice.next >= 0) {
            assert(!wasEof);
            // here we know that slice.size may not change any more
            if (wasSize >= slice.size) { // did not grow since we started copying
                sliceOffset += wasSize;
                sid = slice.next;
            }
        } else if (wasSize >= slice.size) { // did not grow
            break;
        }
    }

    if (!wasEof) {
        debugs(20, 7, "mem-loaded " << e.mem_obj->endOffset() << '/' <<
               anchor.basics.swap_file_sz << " bytes of " << e);
        return true;
    }

    if (anchor.writerHalted) {
        debugs(20, 5, "mem-loaded aborted " << e.mem_obj->endOffset() << '/' <<
               anchor.basics.swap_file_sz << " bytes of " << e);
        return false;
    }

    debugs(20, 5, "mem-loaded all " << e.mem_obj->endOffset() << '/' <<
           anchor.basics.swap_file_sz << " bytes of " << e);

    if (!e.hasParsedReplyHeader())
        throw TextException(ToSBuf("truncated mem-cached headers; accumulated: ", httpHeaderParsingBuffer.length()), Here());

    // from StoreEntry::complete()
    e.mem_obj->object_sz = e.mem_obj->endOffset();
    e.store_status = STORE_OK;
    e.setMemStatus(IN_MEMORY);

    assert(e.mem_obj->object_sz >= 0);
    assert(static_cast<uint64_t>(e.mem_obj->object_sz) == anchor.basics.swap_file_sz);
    // would be nice to call validLength() here, but it needs e.key

    // we read the entire response into the local memory; no more need to lock
    disconnect(e);
    return true;
}

/// imports one shared memory slice into local memory
void
MemStore::copyFromShmSlice(StoreEntry &e, const StoreIOBuffer &buf)
{
    debugs(20, 7, "buf: " << buf.offset << " + " << buf.length);

    // local memory stores both headers and body so copy regardless of pstate
    const int64_t offBefore = e.mem_obj->endOffset();
    assert(e.mem_obj->data_hdr.write(buf)); // from MemObject::write()
    const int64_t offAfter = e.mem_obj->endOffset();
    // expect to write the entire buf because StoreEntry::write() never fails
    assert(offAfter >= 0 && offBefore <= offAfter &&
           static_cast<size_t>(offAfter - offBefore) == buf.length);
}

/// whether we should cache the entry
bool
MemStore::shouldCache(StoreEntry &e) const
{
    if (e.mem_status == IN_MEMORY) {
        debugs(20, 5, "already loaded from mem-cache: " << e);
        return false;
    }

    if (e.mem_obj && e.mem_obj->memCache.offset > 0) {
        debugs(20, 5, "already written to mem-cache: " << e);
        return false;
    }

    if (shutting_down) {
        debugs(20, 5, "avoid heavy optional work during shutdown: " << e);
        return false;
    }

    // To avoid SMP workers releasing each other caching attempts, restrict disk
    // caching to StoreEntry publisher. This check goes before memoryCachable()
    // that may incorrectly release() publisher's entry via checkCachable().
    if (Store::Root().transientsReader(e)) {
        debugs(20, 5, "yield to entry publisher: " << e);
        return false;
    }

    if (!e.memoryCachable()) {
        debugs(20, 7, "Not memory cachable: " << e);
        return false; // will not cache due to entry state or properties
    }

    assert(e.mem_obj);

    if (!e.mem_obj->vary_headers.isEmpty()) {
        // XXX: We must store/load SerialisedMetaData to cache Vary in RAM
        debugs(20, 5, "Vary not yet supported: " << e.mem_obj->vary_headers);
        return false;
    }

    const int64_t expectedSize = e.mem_obj->expectedReplySize(); // may be < 0
    const int64_t loadedSize = e.mem_obj->endOffset();
    const int64_t ramSize = max(loadedSize, expectedSize);
    if (ramSize > maxObjectSize()) {
        debugs(20, 5, "Too big max(" <<
               loadedSize << ", " << expectedSize << "): " << e);
        return false; // will not cache due to cachable entry size limits
    }

    if (!e.mem_obj->isContiguous()) {
        debugs(20, 5, "not contiguous");
        return false;
    }

    if (!map) {
        debugs(20, 5, "No map to mem-cache " << e);
        return false;
    }

    if (EBIT_TEST(e.flags, ENTRY_SPECIAL)) {
        debugs(20, 5, "Not mem-caching ENTRY_SPECIAL " << e);
        return false;
    }

    return true;
}

/// locks map anchor and preps to store the entry in shared memory
bool
MemStore::startCaching(StoreEntry &e)
{
    sfileno index = 0;
    Ipc::StoreMapAnchor *slot = map->openForWriting(reinterpret_cast<const cache_key *>(e.key), index);
    if (!slot) {
        debugs(20, 5, "No room in mem-cache map to index " << e);
        return false;
    }

    assert(e.mem_obj);
    e.mem_obj->memCache.index = index;
    e.mem_obj->memCache.io = Store::ioWriting;
    slot->set(e);
    // Do not allow others to feed off an unknown-size entry because we will
    // stop swapping it out if it grows too large.
    if (e.mem_obj->expectedReplySize() >= 0)
        map->startAppending(index);
    e.memOutDecision(true);
    return true;
}

/// copies all local data to shared memory
void
MemStore::copyToShm(StoreEntry &e)
{
    assert(map);
    assert(e.mem_obj);
    Must(!EBIT_TEST(e.flags, ENTRY_FWD_HDR_WAIT));

    const int64_t eSize = e.mem_obj->endOffset();
    if (e.mem_obj->memCache.offset >= eSize) {
        debugs(20, 5, "postponing copying " << e << " for lack of news: " <<
               e.mem_obj->memCache.offset << " >= " << eSize);
        return; // nothing to do (yet)
    }

    // throw if an accepted unknown-size entry grew too big or max-size changed
    Must(eSize <= maxObjectSize());

    const int32_t index = e.mem_obj->memCache.index;
    assert(index >= 0);
    Ipc::StoreMapAnchor &anchor = map->writeableEntry(index);
    lastWritingSlice = anchor.start;

    // fill, skip slices that are already full
    // Optimize: remember lastWritingSlice in e.mem_obj
    while (e.mem_obj->memCache.offset < eSize) {
        Ipc::StoreMap::Slice &slice = nextAppendableSlice(
                                          e.mem_obj->memCache.index, lastWritingSlice);
        if (anchor.start < 0)
            anchor.start = lastWritingSlice;
        copyToShmSlice(e, anchor, slice);
    }

    debugs(20, 7, "mem-cached available " << eSize << " bytes of " << e);
}

/// copies at most one slice worth of local memory to shared memory
void
MemStore::copyToShmSlice(StoreEntry &e, Ipc::StoreMapAnchor &anchor, Ipc::StoreMap::Slice &slice)
{
    Ipc::Mem::PageId page = pageForSlice(lastWritingSlice);
    debugs(20, 7, "entry " << e << " slice " << lastWritingSlice << " has " <<
           page);

    const int64_t bufSize = Ipc::Mem::PageSize();
    const int64_t sliceOffset = e.mem_obj->memCache.offset % bufSize;
    StoreIOBuffer sharedSpace(bufSize - sliceOffset, e.mem_obj->memCache.offset,
                              static_cast<char*>(PagePointer(page)) + sliceOffset);

    // check that we kept everything or purge incomplete/sparse cached entry
    const ssize_t copied = e.mem_obj->data_hdr.copy(sharedSpace);
    if (copied <= 0) {
        debugs(20, 2, "Failed to mem-cache " << (bufSize - sliceOffset) <<
               " bytes of " << e << " from " << e.mem_obj->memCache.offset <<
               " in " << page);
        throw TexcHere("data_hdr.copy failure");
    }

    debugs(20, 7, "mem-cached " << copied << " bytes of " << e <<
           " from " << e.mem_obj->memCache.offset << " in " << page);

    slice.size += copied;
    e.mem_obj->memCache.offset += copied;
    anchor.basics.swap_file_sz = e.mem_obj->memCache.offset;
}

/// starts checking with the entry chain slice at a given offset and
/// returns a not-full (but not necessarily empty) slice, updating sliceOffset
Ipc::StoreMap::Slice &
MemStore::nextAppendableSlice(const sfileno fileNo, sfileno &sliceOffset)
{
    // allocate the very first slot for the entry if needed
    if (sliceOffset < 0) {
        Ipc::StoreMapAnchor &anchor = map->writeableEntry(fileNo);
        Must(anchor.start < 0);
        Ipc::Mem::PageId page;
        sliceOffset = reserveSapForWriting(page); // throws
        extras->items[sliceOffset].page = page;
        anchor.start = sliceOffset;
    }

    const size_t sliceCapacity = Ipc::Mem::PageSize();
    do {
        Ipc::StoreMap::Slice &slice = map->writeableSlice(fileNo, sliceOffset);

        if (slice.size >= sliceCapacity) {
            if (slice.next >= 0) {
                sliceOffset = slice.next;
                continue;
            }

            Ipc::Mem::PageId page;
            slice.next = sliceOffset = reserveSapForWriting(page);
            extras->items[sliceOffset].page = page;
            debugs(20, 7, "entry " << fileNo << " new slice: " << sliceOffset);
            continue; // to get and return the slice at the new sliceOffset
        }

        return slice;
    } while (true);
    /* not reached */
}

/// safely returns a previously allocated memory page for the given entry slice
Ipc::Mem::PageId
MemStore::pageForSlice(Ipc::StoreMapSliceId sliceId)
{
    Must(extras);
    Must(sliceId >= 0);
    Ipc::Mem::PageId page = extras->items[sliceId].page;
    Must(page);
    return page;
}

/// finds a slot and a free page to fill or throws
sfileno
MemStore::reserveSapForWriting(Ipc::Mem::PageId &page)
{
    Ipc::Mem::PageId slot;
    if (freeSlots->pop(slot)) {
        const auto slotId = slot.number - 1;
        debugs(20, 5, "got a previously free slot: " << slotId);

        if (Ipc::Mem::GetPage(Ipc::Mem::PageId::cachePage, page)) {
            debugs(20, 5, "and got a previously free page: " << page);
            map->prepFreeSlice(slotId);
            return slotId;
        } else {
            debugs(20, 3, "but there is no free page, returning " << slotId);
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
        const auto slotId = slot.number - 1;
        map->prepFreeSlice(slotId);
        debugs(20, 5, "got previously busy " << slotId << " and " << page);
        return slotId;
    }
    assert(waitingFor.slot == &slot && waitingFor.page == &page);
    waitingFor.slot = nullptr;
    waitingFor.page = nullptr;

    debugs(47, 3, "cannot get a slice; entries: " << map->entryCount());
    throw TexcHere("ran out of mem-cache slots");
}

void
MemStore::noteFreeMapSlice(const Ipc::StoreMapSliceId sliceId)
{
    Ipc::Mem::PageId &pageId = extras->items[sliceId].page;
    debugs(20, 9, "slice " << sliceId << " freed " << pageId);
    assert(pageId);
    Ipc::Mem::PageId slotId;
    slotId.pool = Ipc::Mem::PageStack::IdForMemStoreSpace();
    slotId.number = sliceId + 1;
    if (!waitingFor) {
        // must zero pageId before we give slice (and pageId extras!) to others
        Ipc::Mem::PutPage(pageId);
        freeSlots->push(slotId);
    } else {
        *waitingFor.slot = slotId;
        *waitingFor.page = pageId;
        waitingFor.slot = nullptr;
        waitingFor.page = nullptr;
        pageId = Ipc::Mem::PageId();
    }
}

void
MemStore::write(StoreEntry &e)
{
    assert(e.mem_obj);

    debugs(20, 7, "entry " << e);

    switch (e.mem_obj->memCache.io) {
    case Store::ioUndecided:
        if (!shouldCache(e) || !startCaching(e)) {
            e.mem_obj->memCache.io = Store::ioDone;
            e.memOutDecision(false);
            return;
        }
        break;

    case Store::ioDone:
    case Store::ioReading:
        return; // we should not write in all of the above cases

    case Store::ioWriting:
        break; // already decided to write and still writing
    }

    try {
        copyToShm(e);
        if (e.store_status == STORE_OK) // done receiving new content
            completeWriting(e);
        else
            CollapsedForwarding::Broadcast(e);
        return;
    } catch (const std::exception &x) { // TODO: should we catch ... as well?
        debugs(20, 2, "mem-caching error writing entry " << e << ": " << x.what());
        // fall through to the error handling code
    }

    disconnect(e);
}

void
MemStore::completeWriting(StoreEntry &e)
{
    assert(e.mem_obj);
    const int32_t index = e.mem_obj->memCache.index;
    assert(index >= 0);
    assert(map);

    debugs(20, 5, "mem-cached all " << e.mem_obj->memCache.offset << " bytes of " << e);

    e.mem_obj->memCache.index = -1;
    e.mem_obj->memCache.io = Store::ioDone;
    map->closeForWriting(index);

    CollapsedForwarding::Broadcast(e);
    e.storeWriterDone();
}

void
MemStore::evictCached(StoreEntry &e)
{
    debugs(47, 5, e);
    if (e.hasMemStore()) {
        if (map->freeEntry(e.mem_obj->memCache.index))
            CollapsedForwarding::Broadcast(e);
        if (!e.locked()) {
            disconnect(e);
            e.destroyMemObject();
        }
    } else if (const auto key = e.publicKey()) {
        // the entry may have been loaded and then disconnected from the cache
        evictIfFound(key);
        if (!e.locked())
            e.destroyMemObject();
    }
}

void
MemStore::evictIfFound(const cache_key *key)
{
    if (map)
        map->freeEntryByKey(key);
}

void
MemStore::disconnect(StoreEntry &e)
{
    assert(e.mem_obj);
    MemObject &mem_obj = *e.mem_obj;
    if (e.hasMemStore()) {
        if (mem_obj.memCache.io == Store::ioWriting) {
            map->abortWriting(mem_obj.memCache.index);
            mem_obj.memCache.index = -1;
            mem_obj.memCache.io = Store::ioDone;
            CollapsedForwarding::Broadcast(e);
            e.storeWriterDone();
        } else {
            assert(mem_obj.memCache.io == Store::ioReading);
            map->closeForReading(mem_obj.memCache.index);
            mem_obj.memCache.index = -1;
            mem_obj.memCache.io = Store::ioDone;
        }
    }
}

bool
MemStore::Requested()
{
    return Config.memShared && Config.memMaxSize > 0;
}

/// calculates maximum number of entries we need to store and map
int64_t
MemStore::EntryLimit()
{
    if (!Requested())
        return 0;

    const int64_t minEntrySize = Ipc::Mem::PageSize();
    const int64_t entryLimit = Config.memMaxSize / minEntrySize;
    return entryLimit;
}

/// reports our needs for shared memory pages to Ipc::Mem::Pages;
/// decides whether to use a shared memory cache or checks its configuration;
/// and initializes shared memory segments used by MemStore
class MemStoreRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    MemStoreRr(): spaceOwner(nullptr), mapOwner(nullptr), extrasOwner(nullptr) {}
    void finalizeConfig() override;
    void claimMemoryNeeds() override;
    void useConfig() override;
    ~MemStoreRr() override;

protected:
    /* Ipc::Mem::RegisteredRunner API */
    void create() override;

private:
    Ipc::Mem::Owner<Ipc::Mem::PageStack> *spaceOwner; ///< free slices Owner
    MemStoreMap::Owner *mapOwner; ///< primary map Owner
    Ipc::Mem::Owner<MemStoreMapExtras> *extrasOwner; ///< PageIds Owner
};

DefineRunnerRegistrator(MemStoreRr);

void
MemStoreRr::claimMemoryNeeds()
{
    Ipc::Mem::NotePageNeed(Ipc::Mem::PageId::cachePage, MemStore::EntryLimit());
}

void
MemStoreRr::finalizeConfig()
{
    // decide whether to use a shared memory cache if the user did not specify
    if (!Config.memShared.configured()) {
        Config.memShared.configure(Ipc::Mem::Segment::Enabled() && UsingSmp() &&
                                   Config.memMaxSize > 0);
    } else if (Config.memShared && !Ipc::Mem::Segment::Enabled()) {
        fatal("memory_cache_shared is on, but no support for shared memory detected");
    } else if (Config.memShared && !UsingSmp()) {
        debugs(20, DBG_IMPORTANT, "WARNING: memory_cache_shared is on, but only"
               " a single worker is running");
    }

    if (MemStore::Requested() && Config.memMaxSize < Ipc::Mem::PageSize()) {
        debugs(20, DBG_IMPORTANT, "WARNING: mem-cache size is too small (" <<
               (Config.memMaxSize / 1024.0) << " KB), should be >= " <<
               (Ipc::Mem::PageSize() / 1024.0) << " KB");
    }
}

void
MemStoreRr::useConfig()
{
    assert(Config.memShared.configured());
    Ipc::Mem::RegisteredRunner::useConfig();
}

void
MemStoreRr::create()
{
    if (!MemStore::Enabled())
        return;

    const int64_t entryLimit = MemStore::EntryLimit();
    assert(entryLimit > 0);

    Ipc::Mem::PageStack::Config spaceConfig;
    spaceConfig.poolId = Ipc::Mem::PageStack::IdForMemStoreSpace();
    spaceConfig.pageSize = 0; // the pages are stored in Ipc::Mem::Pages
    spaceConfig.capacity = entryLimit;
    spaceConfig.createFull = true; // all pages are initially available
    Must(!spaceOwner);
    spaceOwner = shm_new(Ipc::Mem::PageStack)(SpaceLabel, spaceConfig);
    Must(!mapOwner);
    mapOwner = MemStoreMap::Init(SBuf(MapLabel), entryLimit);
    Must(!extrasOwner);
    extrasOwner = shm_new(MemStoreMapExtras)(ExtrasLabel, entryLimit);
}

MemStoreRr::~MemStoreRr()
{
    delete extrasOwner;
    delete mapOwner;
    delete spaceOwner;
}

