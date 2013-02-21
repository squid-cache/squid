/*
 * DEBUG: section 20    Storage Manager
 *
 */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "HttpReply.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/Pages.h"
#include "MemObject.h"
#include "Transients.h"
#include "mime_header.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "StoreStats.h"
#include "tools.h"

#if HAVE_LIMITS_H
#include <limits>
#endif


/// shared memory segment path to use for Transients maps
static const char *MapLabel = "transients_map";


Transients::Transients(): map(NULL)
{
debugs(0,0, "Transients::ctor");
}

Transients::~Transients()
{
    delete map;
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
}

bool
Transients::dereference(StoreEntry &, bool)
{
    // no need to keep e in the global store_table for us; we have our own map
    return false;
}

int
Transients::callback()
{
    return 0;
}

StoreSearch *
Transients::search(String const, HttpRequest *)
{
    fatal("not implemented");
    return NULL;
}

StoreEntry *
Transients::get(const cache_key *key)
{
    if (!map)
        return NULL;

    sfileno index;
    if (!map->openForReading(key, index))
        return NULL;

    const TransientsMap::Extras &extras = map->extras(index);

    // create a brand new store entry and initialize it with stored info
    StoreEntry *e = storeCreateEntry(extras.url, extras.url,
                                     extras.reqFlags, extras.reqMethod);
    // XXX: overwriting storeCreateEntry() because we are expected to return an unlocked entry
    // TODO: move locking from storeCreateEntry to callers as a mid-term solution
    e->lock_count = 0;

    assert(e->mem_obj);
    e->mem_obj->method = extras.reqMethod;

    // we copied everything we could to local memory; no more need to lock
    map->closeForReading(index);

    // XXX: overwriting storeCreateEntry() which calls setPrivateKey() if
    // neighbors_do_private_keys (which is true in most cases and by default).
    // This is nothing but waste of CPU cycles. Need a better API to avoid it.
    e->setPublicKey();

    assert(e->next); // e->hashInsert(key) is done in setPublicKey()
    return e;
}

void
Transients::get(String const key, STOREGETCLIENT aCallback, void *aCallbackData)
{
    // XXX: not needed but Store parent forces us to implement this
    fatal("Transients::get(key,callback,data) should not be called");
}

void
Transients::put(StoreEntry *e, const RequestFlags &reqFlags,
                const HttpRequestMethod &reqMethod)
{
    assert(e);

    if (!map) {
        debugs(20, 5, "No map to add " << *e);
        return;
	}

    sfileno index = 0;
    Ipc::StoreMapAnchor *slot = map->openForWriting(reinterpret_cast<const cache_key *>(e->key), index);
    if (!slot) {
        debugs(20, 5, "No room in map to index " << *e);
        return;
	}

    try {
        if (copyToShm(*e, index, reqFlags, reqMethod)) {
            slot->set(*e);
            map->closeForWriting(index, false);
            return;
		}
        // fall through to the error handling code
	} 
    catch (const std::exception &x) { // TODO: should we catch ... as well?
        debugs(20, 2, "error keeping entry " << index <<
               ' ' << *e << ": " << x.what());
        // fall through to the error handling code
	}

    map->abortIo(index);
}


/// copies all relevant local data to shared memory
bool
Transients::copyToShm(const StoreEntry &e, const sfileno index,
                      const RequestFlags &reqFlags,
                      const HttpRequestMethod &reqMethod)
{
    TransientsMap::Extras &extras = map->extras(index);

    const char *url = e.url();
    const size_t urlLen = strlen(url);
    Must(urlLen < sizeof(extras.url)); // we have space to store it all, plus 0
    strncpy(extras.url, url, sizeof(extras.url));
	extras.url[urlLen] = '\0';

    extras.reqFlags = reqFlags;
    

    Must(reqMethod != Http::METHOD_OTHER);
    extras.reqMethod = reqMethod.id();

    return true;
}

void
Transients::noteFreeMapSlice(const sfileno sliceId)
{
    // TODO: we should probably find the entry being deleted and abort it
}

/// calculates maximum number of entries we need to store and map
int64_t
Transients::EntryLimit()
{
    // TODO: we should also check whether any SMP-aware caching is configured
    if (!UsingSmp() || !Config.onoff.collapsed_forwarding)
        return 0; // no SMP collapsed forwarding possible or needed

    return 16*1024; // XXX: make configurable
}

/// initializes shared memory segment used by Transients
class TransientsRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    TransientsRr(): mapOwner(NULL) {}
    virtual void run(const RunnerRegistry &);
    virtual ~TransientsRr();

protected:
    virtual void create(const RunnerRegistry &);

private:
    TransientsMap::Owner *mapOwner;
};

RunnerRegistrationEntry(rrAfterConfig, TransientsRr);

void TransientsRr::run(const RunnerRegistry &r)
{
    assert(Config.memShared.configured());
    Ipc::Mem::RegisteredRunner::run(r);
}

void TransientsRr::create(const RunnerRegistry &)
{
debugs(0,0, "TransientsRr::create1: " << Config.onoff.collapsed_forwarding);
    if (!Config.onoff.collapsed_forwarding)
        return;

    const int64_t entryLimit = Transients::EntryLimit();
debugs(0,0, "TransientsRr::create2: " << entryLimit);
    if (entryLimit <= 0)
        return; // no SMP configured or a misconfiguration

    Must(!mapOwner);
    mapOwner = TransientsMap::Init(MapLabel, entryLimit);
}

TransientsRr::~TransientsRr()
{
    delete mapOwner;
}
