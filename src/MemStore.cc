/*
 * $Id$
 *
 * DEBUG: section 20    Memory Cache
 *
 */

#include "config.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/Pages.h"
#include "MemObject.h"
#include "MemStore.h"
#include "HttpReply.h"


// XXX: support storage using more than one page per entry


MemStore::MemStore(): map(NULL)
{
}

MemStore::~MemStore()
{
    delete map;
}

void
MemStore::init()
{
    if (!map && Config.memMaxSize && (!UsingSmp() || IamWorkerProcess())) {
        // TODO: warn if we cannot support the configured maximum entry size
        const int64_t entrySize = Ipc::Mem::PageSize(); // for now
        const int64_t entryCount = Config.memMaxSize / entrySize;
        // TODO: warn if we cannot cache at least one item (misconfiguration)
        if (entryCount > 0)
            map = new MemStoreMap("cache_mem", entryCount);
    }
}

void
MemStore::stat(StoreEntry &output) const
{
    storeAppendPrintf(&output, "Memory Cache");
    // TODO: implement
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
    return 0; // XXX: make configurable
}

void
MemStore::updateSize(int64_t eSize, int sign)
{
    // XXX: irrelevant, but Store parent forces us to implement this
    fatal("MemStore::updateSize should not be called");
}

void
MemStore::reference(StoreEntry &)
{
}

void
MemStore::dereference(StoreEntry &)
{
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

    // XXX: replace sfileno with a bigger word (sfileno is only for cache_dirs)
    sfileno index;
    const Ipc::StoreMapSlot *const slot = map->openForReading(key, index);
    if (!slot)
        return NULL;

    const Ipc::StoreMapSlot::Basics &basics = slot->basics;
    const MemStoreMap::Extras &extras = map->extras(index);

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

    const bool copied = copyFromShm(*e, extras);

    // we copied everything we could to local memory; no more need to lock
    map->closeForReading(index);

    if (copied) {
        e->hashInsert(key);
        return e;
    }

    debugs(20, 3, HERE << "mem-loading failed; freeing " << index);
    map->free(index); // do not let others into the same trap
    return NULL;
}

void
MemStore::get(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    // XXX: not needed but Store parent forces us to implement this
    fatal("MemStore::get(key,callback,data) should not be called");
}

bool
MemStore::copyFromShm(StoreEntry &e, const MemStoreMap::Extras &extras)
{
    const Ipc::Mem::PageId &page = extras.page;

    StoreIOBuffer sourceBuf(extras.storedSize, 0,
                              static_cast<char*>(PagePointer(page)));

    // XXX: We do not know the URLs yet, only the key, but we need to parse and
    // store the response for the Root().get() callers to be happy because they
    // expect IN_MEMORY entries to already have the response headers and body.
    // At least one caller calls createMemObject() if there is not one, so
    // we hide the true object until that happens (to avoid leaking TBD URLs).
    e.createMemObject("TBD", "TBD");

    // emulate the usual Store code but w/o inapplicable checks and callbacks:

    // from store_client::readBody():
    HttpReply *rep = (HttpReply *)e.getReply();
    const ssize_t end = headersEnd(sourceBuf.data, sourceBuf.length);
    if (!rep->parseCharBuf(sourceBuf.data, end)) {
        debugs(20, DBG_IMPORTANT, "Could not parse mem-cached headers: " << e);
        return false;
    }
    // local memory stores both headers and body
    e.mem_obj->object_sz = sourceBuf.length; // from StoreEntry::complete()

    storeGetMemSpace(sourceBuf.length); // from StoreEntry::write()

    assert(e.mem_obj->data_hdr.write(sourceBuf)); // from MemObject::write()
    const int64_t written = e.mem_obj->endOffset();
    assert(written == sourceBuf.length); // StoreEntry::write never fails?
    // would be nice to call validLength() here, but it needs e.key

    debugs(20, 7, HERE << "mem-loaded all " << written << " bytes of " << e <<
           " from " << page);

    e.hideMemObject();

    return true;
}

void
MemStore::considerKeeping(StoreEntry &e)
{
    if (!e.memoryCachable()) {
        debugs(20, 7, HERE << "Not memory cachable: " << e);
        return; // cannot keep due to entry state or properties
    }

    assert(e.mem_obj);
    if (!willFit(e.mem_obj->endOffset())) {
        debugs(20, 5, HERE << "No mem-cache space for " << e);
        return; // failed to free enough space
    }

    keep(e); // may still fail
}

bool
MemStore::willFit(int64_t need)
{
    // TODO: obey configured maximum entry size (with page-based rounding)
    return need <= Ipc::Mem::PageSize();
}

/// allocates map slot and calls copyToShm to store the entry in shared memory
void
MemStore::keep(StoreEntry &e)
{
    if (!map) {
        debugs(20, 5, HERE << "No map to mem-cache " << e);
        return;
    }

    sfileno index = 0;
    Ipc::StoreMapSlot *slot = map->openForWriting(reinterpret_cast<const cache_key *>(e.key), index);
    if (!slot) {
        debugs(20, 5, HERE << "No room in mem-cache map to index " << e);
        return;
    }

    MemStoreMap::Extras &extras = map->extras(index);
    if (copyToShm(e, extras)) {
        slot->set(e);
        map->closeForWriting(index, false);
    } else {
        map->abortIo(index);
    }
}

/// uses mem_hdr::copy() to copy local data to shared memory
bool
MemStore::copyToShm(StoreEntry &e, MemStoreMap::Extras &extras)
{
    Ipc::Mem::PageId page;
    if (!Ipc::Mem::GetPage(page)) {
        debugs(20, 5, HERE << "No mem-cache page for " << e);
        return false; // GetPage is responsible for any cleanup on failures
    }

    const int64_t bufSize = Ipc::Mem::PageSize();
    const int64_t eSize = e.mem_obj->endOffset();

    StoreIOBuffer sharedSpace(bufSize, 0,
                              static_cast<char*>(PagePointer(page)));
    
    // check that we kept everything or purge incomplete/sparse cached entry
    const ssize_t copied = e.mem_obj->data_hdr.copy(sharedSpace);
    if (eSize != copied) {
        debugs(20, 2, HERE << "Failed to mem-cache " << e << ": " <<
               eSize << "!=" << copied);
        // cleanup
        PutPage(page);
        return false;
    }

    debugs(20, 7, HERE << "mem-cached all " << eSize << " bytes of " << e <<
           " in " << page);

    // remember storage location and size
    extras.page = page;
    extras.storedSize = copied;
    return true;
}
