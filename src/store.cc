/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager */

#include "squid.h"
#include "base/TextException.h"
#include "CacheDigest.h"
#include "CacheManager.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "ETag.h"
#include "event.h"
#include "fde.h"
#include "globals.h"
#include "http.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "mem_node.h"
#include "MemObject.h"
#include "MemStore.h"
#include "mgr/Registration.h"
#include "mgr/StoreIoAction.h"
#include "profiler/Profiler.h"
#include "repl_modules.h"
#include "RequestFlags.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "stmem.h"
#include "Store.h"
#include "store/Controller.h"
#include "store/Disk.h"
#include "store/Disks.h"
#include "store_digest.h"
#include "store_key_md5.h"
#include "store_log.h"
#include "store_rebuild.h"
#include "StoreClient.h"
#include "StoreIOState.h"
#include "StoreMeta.h"
#include "StrList.h"
#include "swap_log_op.h"
#include "tools.h"
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

/** StoreEntry uses explicit new/delete operators, which set pool chunk size to 2MB
 * XXX: convert to MEMPROXY_CLASS() API
 */
#include "mem/Pool.h"

#include <climits>
#include <stack>

#define REBUILD_TIMESTAMP_DELTA_MAX 2

#define STORE_IN_MEM_BUCKETS            (229)

// TODO: Convert these string constants to enum string-arrays generated

const char *memStatusStr[] = {
    "NOT_IN_MEMORY",
    "IN_MEMORY"
};

const char *pingStatusStr[] = {
    "PING_NONE",
    "PING_WAITING",
    "PING_DONE"
};

const char *storeStatusStr[] = {
    "STORE_OK",
    "STORE_PENDING"
};

const char *swapStatusStr[] = {
    "SWAPOUT_NONE",
    "SWAPOUT_WRITING",
    "SWAPOUT_DONE",
    "SWAPOUT_FAILED"
};

/*
 * This defines an repl type
 */

typedef struct _storerepl_entry storerepl_entry_t;

struct _storerepl_entry {
    const char *typestr;
    REMOVALPOLICYCREATE *create;
};

static storerepl_entry_t *storerepl_list = NULL;

/*
 * local function prototypes
 */
static int getKeyCounter(void);
static OBJH storeCheckCachableStats;
static EVH storeLateRelease;

/*
 * local variables
 */
static std::stack<StoreEntry*> LateReleaseStack;
MemAllocator *StoreEntry::pool = NULL;

void
Store::Stats(StoreEntry * output)
{
    assert(output);
    Root().stat(*output);
}

// XXX: new/delete operators need to be replaced with MEMPROXY_CLASS
// definitions but doing so exposes bug 4370, and maybe 4354 and 4355
void *
StoreEntry::operator new (size_t bytecount)
{
    assert(bytecount == sizeof (StoreEntry));

    if (!pool) {
        pool = memPoolCreate ("StoreEntry", bytecount);
    }

    return pool->alloc();
}

void
StoreEntry::operator delete (void *address)
{
    pool->freeOne(address);
}

bool
StoreEntry::makePublic(const KeyScope scope)
{
    /* This object can be cached for a long time */
    return !EBIT_TEST(flags, RELEASE_REQUEST) && setPublicKey(scope);
}

void
StoreEntry::makePrivate(const bool shareable)
{
    releaseRequest(shareable); /* delete object when not used */
}

void
StoreEntry::clearPrivate()
{
    assert(!EBIT_TEST(flags, RELEASE_REQUEST));
    EBIT_CLR(flags, KEY_PRIVATE);
    shareableWhenPrivate = false;
}

bool
StoreEntry::cacheNegatively()
{
    /* This object may be negatively cached */
    if (makePublic()) {
        negativeCache();
        return true;
    }
    return false;
}

size_t
StoreEntry::inUseCount()
{
    if (!pool)
        return 0;
    return pool->getInUseCount();
}

const char *
StoreEntry::getMD5Text() const
{
    return storeKeyText((const cache_key *)key);
}

#include "comm.h"

void
StoreEntry::DeferReader(void *theContext, CommRead const &aRead)
{
    StoreEntry *anEntry = (StoreEntry *)theContext;
    anEntry->delayAwareRead(aRead.conn,
                            aRead.buf,
                            aRead.len,
                            aRead.callback);
}

void
StoreEntry::delayAwareRead(const Comm::ConnectionPointer &conn, char *buf, int len, AsyncCall::Pointer callback)
{
    size_t amountToRead = bytesWanted(Range<size_t>(0, len));
    /* sketch: readdeferer* = getdeferer.
     * ->deferRead (fd, buf, len, callback, DelayAwareRead, this)
     */

    if (amountToRead <= 0) {
        assert (mem_obj);
        mem_obj->delayRead(DeferredRead(DeferReader, this, CommRead(conn, buf, len, callback)));
        return;
    }

    if (fd_table[conn->fd].closing()) {
        // Readers must have closing callbacks if they want to be notified. No
        // readers appeared to care around 2009/12/14 as they skipped reading
        // for other reasons. Closing may already be true at the delyaAwareRead
        // call time or may happen while we wait after delayRead() above.
        debugs(20, 3, "will not read from closing " << conn << " for " << callback);
        return; // the read callback will never be called
    }

    comm_read(conn, buf, amountToRead, callback);
}

size_t
StoreEntry::bytesWanted (Range<size_t> const aRange, bool ignoreDelayPools) const
{
    if (mem_obj == NULL)
        return aRange.end;

#if URL_CHECKSUM_DEBUG

    mem_obj->checkUrlChecksum();

#endif

    if (!mem_obj->readAheadPolicyCanRead())
        return 0;

    return mem_obj->mostBytesWanted(aRange.end, ignoreDelayPools);
}

bool
StoreEntry::checkDeferRead(int) const
{
    return (bytesWanted(Range<size_t>(0,INT_MAX)) == 0);
}

void
StoreEntry::setNoDelay(bool const newValue)
{
    if (mem_obj)
        mem_obj->setNoDelay(newValue);
}

// XXX: Type names mislead. STORE_DISK_CLIENT actually means that we should
//      open swapin file, aggressively trim memory, and ignore read-ahead gap.
//      It does not mean we will read from disk exclusively (or at all!).
//      STORE_MEM_CLIENT covers all other cases, including in-memory entries,
//      newly created entries, and entries not backed by disk or memory cache.
// XXX: May create STORE_DISK_CLIENT with no disk caching configured.
// XXX: Collapsed clients cannot predict their type.
store_client_t
StoreEntry::storeClientType() const
{
    /* The needed offset isn't in memory
     * XXX TODO: this is wrong for range requests
     * as the needed offset may *not* be 0, AND
     * offset 0 in the memory object is the HTTP headers.
     */

    assert(mem_obj);

    if (mem_obj->inmem_lo)
        return STORE_DISK_CLIENT;

    if (EBIT_TEST(flags, ENTRY_ABORTED)) {
        /* I don't think we should be adding clients to aborted entries */
        debugs(20, DBG_IMPORTANT, "storeClientType: adding to ENTRY_ABORTED entry");
        return STORE_MEM_CLIENT;
    }

    if (swapoutFailed())
        return STORE_MEM_CLIENT;

    if (store_status == STORE_OK) {
        /* the object has completed. */

        if (mem_obj->inmem_lo == 0 && !isEmpty()) {
            if (swappedOut()) {
                debugs(20,7, HERE << mem_obj << " lo: " << mem_obj->inmem_lo << " hi: " << mem_obj->endOffset() << " size: " << mem_obj->object_sz);
                if (mem_obj->endOffset() == mem_obj->object_sz) {
                    /* hot object fully swapped in (XXX: or swapped out?) */
                    return STORE_MEM_CLIENT;
                }
            } else {
                /* Memory-only, or currently being swapped out */
                return STORE_MEM_CLIENT;
            }
        }
        return STORE_DISK_CLIENT;
    }

    /* here and past, entry is STORE_PENDING */
    /*
     * If this is the first client, let it be the mem client
     */
    if (mem_obj->nclients == 1)
        return STORE_MEM_CLIENT;

    /*
     * If there is no disk file to open yet, we must make this a
     * mem client.  If we can't open the swapin file before writing
     * to the client, there is no guarantee that we will be able
     * to open it later when we really need it.
     */
    if (swap_status == SWAPOUT_NONE)
        return STORE_MEM_CLIENT;

    /*
     * otherwise, make subsequent clients read from disk so they
     * can not delay the first, and vice-versa.
     */
    return STORE_DISK_CLIENT;
}

StoreEntry::StoreEntry() :
    mem_obj(NULL),
    timestamp(-1),
    lastref(-1),
    expires(-1),
    lastModified_(-1),
    swap_file_sz(0),
    refcount(0),
    flags(0),
    swap_filen(-1),
    swap_dirn(-1),
    mem_status(NOT_IN_MEMORY),
    ping_status(PING_NONE),
    store_status(STORE_PENDING),
    swap_status(SWAPOUT_NONE),
    lock_count(0),
    shareableWhenPrivate(false)
{
    debugs(20, 5, "StoreEntry constructed, this=" << this);
}

StoreEntry::~StoreEntry()
{
    debugs(20, 5, "StoreEntry destructed, this=" << this);
}

#if USE_ADAPTATION
void
StoreEntry::deferProducer(const AsyncCall::Pointer &producer)
{
    if (!deferredProducer)
        deferredProducer = producer;
    else
        debugs(20, 5, "Deferred producer call is already set to: " <<
               *deferredProducer << ", requested call: " << *producer);
}

void
StoreEntry::kickProducer()
{
    if (deferredProducer != NULL) {
        ScheduleCallHere(deferredProducer);
        deferredProducer = NULL;
    }
}
#endif

void
StoreEntry::destroyMemObject()
{
    debugs(20, 3, mem_obj << " in " << *this);

    // Store::Root() is FATALly missing during shutdown
    if (hasTransients() && !shutting_down)
        Store::Root().transientsDisconnect(*this);
    if (hasMemStore() && !shutting_down)
        Store::Root().memoryDisconnect(*this);

    if (auto memObj = mem_obj) {
        setMemStatus(NOT_IN_MEMORY);
        mem_obj = NULL;
        delete memObj;
    }
}

void
destroyStoreEntry(void *data)
{
    debugs(20, 3, HERE << "destroyStoreEntry: destroying " <<  data);
    StoreEntry *e = static_cast<StoreEntry *>(static_cast<hash_link *>(data));
    assert(e != NULL);

    // Store::Root() is FATALly missing during shutdown
    if (e->hasDisk() && !shutting_down)
        e->disk().disconnect(*e);

    e->destroyMemObject();

    e->hashDelete();

    assert(e->key == NULL);

    delete e;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

void
StoreEntry::hashInsert(const cache_key * someKey)
{
    debugs(20, 3, "StoreEntry::hashInsert: Inserting Entry " << *this << " key '" << storeKeyText(someKey) << "'");
    assert(!key);
    key = storeKeyDup(someKey);
    hash_join(store_table, this);
}

void
StoreEntry::hashDelete()
{
    if (key) { // some test cases do not create keys and do not hashInsert()
        hash_remove_link(store_table, this);
        storeKeyFree((const cache_key *)key);
        key = NULL;
    }
}

/* -------------------------------------------------------------------------- */

void
StoreEntry::lock(const char *context)
{
    ++lock_count;
    debugs(20, 3, context << " locked key " << getMD5Text() << ' ' << *this);
}

void
StoreEntry::touch()
{
    lastref = squid_curtime;
}

void
StoreEntry::releaseRequest(const bool shareable)
{
    debugs(20, 3, shareable << ' ' << *this);
    if (!shareable)
        shareableWhenPrivate = false; // may already be false
    if (EBIT_TEST(flags, RELEASE_REQUEST))
        return;
    setPrivateKey(shareable, true);
}

int
StoreEntry::unlock(const char *context)
{
    debugs(20, 3, (context ? context : "somebody") <<
           " unlocking key " << getMD5Text() << ' ' << *this);
    assert(lock_count > 0);
    --lock_count;

    if (lock_count)
        return (int) lock_count;

    abandon(context);
    return 0;
}

/// keep the unlocked StoreEntry object in the local store_table (if needed) or
/// delete it (otherwise)
void
StoreEntry::doAbandon(const char *context)
{
    debugs(20, 5, *this << " via " << (context ? context : "somebody"));
    assert(!locked());
    assert(storePendingNClients(this) == 0);

    // Both aborted local writers and aborted local readers (of remote writers)
    // are STORE_PENDING, but aborted readers should never release().
    if (EBIT_TEST(flags, RELEASE_REQUEST) ||
            (store_status == STORE_PENDING && !Store::Root().transientsReader(*this))) {
        this->release();
        return;
    }

    if (EBIT_TEST(flags, KEY_PRIVATE))
        debugs(20, DBG_IMPORTANT, "WARNING: " << __FILE__ << ":" << __LINE__ << ": found KEY_PRIVATE");

    Store::Root().handleIdleEntry(*this); // may delete us
}

void
StoreEntry::getPublicByRequestMethod  (StoreClient *aClient, HttpRequest * request, const HttpRequestMethod& method)
{
    assert (aClient);
    aClient->created(storeGetPublicByRequestMethod(request, method));
}

void
StoreEntry::getPublicByRequest (StoreClient *aClient, HttpRequest * request)
{
    assert (aClient);
    aClient->created(storeGetPublicByRequest(request));
}

void
StoreEntry::getPublic (StoreClient *aClient, const char *uri, const HttpRequestMethod& method)
{
    assert (aClient);
    aClient->created(storeGetPublic(uri, method));
}

StoreEntry *
storeGetPublic(const char *uri, const HttpRequestMethod& method)
{
    return Store::Root().find(storeKeyPublic(uri, method));
}

StoreEntry *
storeGetPublicByRequestMethod(HttpRequest * req, const HttpRequestMethod& method, const KeyScope keyScope)
{
    return Store::Root().find(storeKeyPublicByRequestMethod(req, method, keyScope));
}

StoreEntry *
storeGetPublicByRequest(HttpRequest * req, const KeyScope keyScope)
{
    StoreEntry *e = storeGetPublicByRequestMethod(req, req->method, keyScope);

    if (e == NULL && req->method == Http::METHOD_HEAD)
        /* We can generate a HEAD reply from a cached GET object */
        e = storeGetPublicByRequestMethod(req, Http::METHOD_GET, keyScope);

    return e;
}

static int
getKeyCounter(void)
{
    static int key_counter = 0;

    if (++key_counter < 0)
        key_counter = 1;

    return key_counter;
}

/* RBC 20050104 AFAICT this should become simpler:
 * rather than reinserting with a special key it should be marked
 * as 'released' and then cleaned up when refcounting indicates.
 * the StoreHashIndex could well implement its 'released' in the
 * current manner.
 * Also, clean log writing should skip over ia,t
 * Otherwise, we need a 'remove from the index but not the store
 * concept'.
 */
void
StoreEntry::setPrivateKey(const bool shareable, const bool permanent)
{
    debugs(20, 3, shareable << permanent << ' ' << *this);
    if (permanent)
        EBIT_SET(flags, RELEASE_REQUEST); // may already be set
    if (!shareable)
        shareableWhenPrivate = false; // may already be false

    if (EBIT_TEST(flags, KEY_PRIVATE))
        return;

    if (key) {
        Store::Root().evictCached(*this); // all caches/workers will know
        hashDelete();
    }

    if (mem_obj && mem_obj->hasUris())
        mem_obj->id = getKeyCounter();
    const cache_key *newkey = storeKeyPrivate();

    assert(hash_lookup(store_table, newkey) == NULL);
    EBIT_SET(flags, KEY_PRIVATE);
    shareableWhenPrivate = shareable;
    hashInsert(newkey);
}

bool
StoreEntry::setPublicKey(const KeyScope scope)
{
    debugs(20, 3, *this);
    if (key && !EBIT_TEST(flags, KEY_PRIVATE))
        return true; // already public

    assert(mem_obj);

    /*
     * We can't make RELEASE_REQUEST objects public.  Depending on
     * when RELEASE_REQUEST gets set, we might not be swapping out
     * the object.  If we're not swapping out, then subsequent
     * store clients won't be able to access object data which has
     * been freed from memory.
     *
     * If RELEASE_REQUEST is set, setPublicKey() should not be called.
     */
#if MORE_DEBUG_OUTPUT

    if (EBIT_TEST(flags, RELEASE_REQUEST))
        debugs(20, DBG_IMPORTANT, "assertion failed: RELEASE key " << key << ", url " << mem_obj->url);

#endif

    assert(!EBIT_TEST(flags, RELEASE_REQUEST));

    try {
        EntryGuard newVaryMarker(adjustVary(), "setPublicKey+failure");
        const cache_key *pubKey = calcPublicKey(scope);
        Store::Root().addWriting(this, pubKey);
        forcePublicKey(pubKey);
        newVaryMarker.unlockAndReset("setPublicKey+success");
        return true;
    } catch (const std::exception &ex) {
        debugs(20, 2, "for " << *this << " failed: " << ex.what());
    }
    return false;
}

void
StoreEntry::clearPublicKeyScope()
{
    if (!key || EBIT_TEST(flags, KEY_PRIVATE))
        return; // probably the old public key was deleted or made private

    // TODO: adjustVary() when collapsed revalidation supports that

    const cache_key *newKey = calcPublicKey(ksDefault);
    if (!storeKeyHashCmp(key, newKey))
        return; // probably another collapsed revalidation beat us to this change

    forcePublicKey(newKey);
}

/// Unconditionally sets public key for this store entry.
/// Releases the old entry with the same public key (if any).
void
StoreEntry::forcePublicKey(const cache_key *newkey)
{
    debugs(20, 3, storeKeyText(newkey) << " for " << *this);
    assert(mem_obj);

    if (StoreEntry *e2 = (StoreEntry *)hash_lookup(store_table, newkey)) {
        assert(e2 != this);
        debugs(20, 3, "releasing clashing " << *e2);
        e2->release(true);
    }

    if (key)
        hashDelete();

    clearPrivate();

    assert(mem_obj->hasUris());
    hashInsert(newkey);

    if (hasDisk())
        storeDirSwapLog(this, SWAP_LOG_ADD);
}

/// Calculates correct public key for feeding forcePublicKey().
/// Assumes adjustVary() has been called for this entry already.
const cache_key *
StoreEntry::calcPublicKey(const KeyScope keyScope)
{
    assert(mem_obj);
    return mem_obj->request ? storeKeyPublicByRequest(mem_obj->request.getRaw(), keyScope) :
           storeKeyPublic(mem_obj->storeId(), mem_obj->method, keyScope);
}

/// Updates mem_obj->request->vary_headers to reflect the current Vary.
/// The vary_headers field is used to calculate the Vary marker key.
/// Releases the old Vary marker with an outdated key (if any).
/// \returns new (locked) Vary marker StoreEntry or, if none was needed, nil
/// \throws std::exception on failures
StoreEntry *
StoreEntry::adjustVary()
{
    assert(mem_obj);

    if (!mem_obj->request)
        return nullptr;

    HttpRequestPointer request(mem_obj->request);
    const auto &reply = mem_obj->freshestReply();

    if (mem_obj->vary_headers.isEmpty()) {
        /* First handle the case where the object no longer varies */
        request->vary_headers.clear();
    } else {
        if (!request->vary_headers.isEmpty() && request->vary_headers.cmp(mem_obj->vary_headers) != 0) {
            /* Oops.. the variance has changed. Kill the base object
             * to record the new variance key
             */
            request->vary_headers.clear();       /* free old "bad" variance key */
            if (StoreEntry *pe = storeGetPublic(mem_obj->storeId(), mem_obj->method))
                pe->release(true);
        }

        /* Make sure the request knows the variance status */
        if (request->vary_headers.isEmpty())
            request->vary_headers = httpMakeVaryMark(request.getRaw(), &reply);
    }

    // TODO: storeGetPublic() calls below may create unlocked entries.
    // We should add/use storeHas() API or lock/unlock those entries.
    if (!mem_obj->vary_headers.isEmpty() && !storeGetPublic(mem_obj->storeId(), mem_obj->method)) {
        /* Create "vary" base object */
        StoreEntry *pe = storeCreateEntry(mem_obj->storeId(), mem_obj->logUri(), request->flags, request->method);
        // XXX: storeCreateEntry() already tries to make `pe` public under
        // certain conditions. If those conditions do not apply to Vary markers,
        // then refactor to call storeCreatePureEntry() above.  Otherwise,
        // refactor to simply check whether `pe` is already public below.
        if (!pe->makePublic()) {
            pe->unlock("StoreEntry::adjustVary+failed_makePublic");
            throw TexcHere("failed to make Vary marker public");
        }
        /* We are allowed to do this typecast */
        const HttpReplyPointer rep(new HttpReply);
        rep->setHeaders(Http::scOkay, "Internal marker object", "x-squid-internal/vary", -1, -1, squid_curtime + 100000);
        auto vary = reply.header.getList(Http::HdrType::VARY);

        if (vary.size()) {
            /* Again, we own this structure layout */
            rep->header.putStr(Http::HdrType::VARY, vary.termedBuf());
            vary.clean();
        }

#if X_ACCELERATOR_VARY
        vary = reply.header.getList(Http::HdrType::HDR_X_ACCELERATOR_VARY);

        if (vary.size() > 0) {
            /* Again, we own this structure layout */
            rep->header.putStr(Http::HdrType::HDR_X_ACCELERATOR_VARY, vary.termedBuf());
            vary.clean();
        }

#endif
        pe->replaceHttpReply(rep, false); // no write until timestampsSet()

        pe->timestampsSet();

        pe->startWriting(); // after timestampsSet()

        pe->complete();

        return pe;
    }
    return nullptr;
}

StoreEntry *
storeCreatePureEntry(const char *url, const char *log_url, const HttpRequestMethod& method)
{
    StoreEntry *e = NULL;
    debugs(20, 3, "storeCreateEntry: '" << url << "'");

    e = new StoreEntry();
    e->createMemObject(url, log_url, method);

    e->store_status = STORE_PENDING;
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = -1;          /* set in StoreEntry::timestampsSet() */
    e->ping_status = PING_NONE;
    EBIT_SET(e->flags, ENTRY_VALIDATED);
    return e;
}

StoreEntry *
storeCreateEntry(const char *url, const char *logUrl, const RequestFlags &flags, const HttpRequestMethod& method)
{
    StoreEntry *e = storeCreatePureEntry(url, logUrl, method);
    e->lock("storeCreateEntry");

    if (!neighbors_do_private_keys && flags.hierarchical && flags.cachable && e->setPublicKey())
        return e;

    e->setPrivateKey(false, !flags.cachable);
    return e;
}

/* Mark object as expired */
void
StoreEntry::expireNow()
{
    debugs(20, 3, "StoreEntry::expireNow: '" << getMD5Text() << "'");
    expires = squid_curtime;
}

void
StoreEntry::write (StoreIOBuffer writeBuffer)
{
    assert(mem_obj != NULL);
    /* This assert will change when we teach the store to update */
    PROF_start(StoreEntry_write);
    assert(store_status == STORE_PENDING);

    // XXX: caller uses content offset, but we also store headers
    writeBuffer.offset += mem_obj->baseReply().hdr_sz;

    debugs(20, 5, "storeWrite: writing " << writeBuffer.length << " bytes for '" << getMD5Text() << "'");
    PROF_stop(StoreEntry_write);
    storeGetMemSpace(writeBuffer.length);
    mem_obj->write(writeBuffer);

    if (EBIT_TEST(flags, ENTRY_FWD_HDR_WAIT) && !mem_obj->readAheadPolicyCanRead()) {
        debugs(20, 3, "allow Store clients to get entry content after buffering too much for " << *this);
        EBIT_CLR(flags, ENTRY_FWD_HDR_WAIT);
    }

    invokeHandlers();
}

/* Append incoming data from a primary server to an entry. */
void
StoreEntry::append(char const *buf, int len)
{
    assert(mem_obj != NULL);
    assert(len >= 0);
    assert(store_status == STORE_PENDING);

    StoreIOBuffer tempBuffer;
    tempBuffer.data = (char *)buf;
    tempBuffer.length = len;
    /*
     * XXX sigh, offset might be < 0 here, but it gets "corrected"
     * later.  This offset crap is such a mess.
     */
    tempBuffer.offset = mem_obj->endOffset() - mem_obj->baseReply().hdr_sz;
    write(tempBuffer);
}

void
StoreEntry::vappendf(const char *fmt, va_list vargs)
{
    LOCAL_ARRAY(char, buf, 4096);
    *buf = 0;
    int x;

    va_list ap;
    /* Fix of bug 753r. The value of vargs is undefined
     * after vsnprintf() returns. Make a copy of vargs
     * in case we loop around and call vsnprintf() again.
     */
    va_copy(ap,vargs);
    errno = 0;
    if ((x = vsnprintf(buf, sizeof(buf), fmt, ap)) < 0) {
        fatal(xstrerr(errno));
        return;
    }
    va_end(ap);

    if (x < static_cast<int>(sizeof(buf))) {
        append(buf, x);
        return;
    }

    // okay, do it the slow way.
    char *buf2 = new char[x+1];
    int y = vsnprintf(buf2, x+1, fmt, vargs);
    assert(y >= 0 && y == x);
    append(buf2, y);
    delete[] buf2;
}

// deprecated. use StoreEntry::appendf() instead.
void
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
    e->vappendf(fmt, args);
    va_end(args);
}

// deprecated. use StoreEntry::appendf() instead.
void
storeAppendVPrintf(StoreEntry * e, const char *fmt, va_list vargs)
{
    e->vappendf(fmt, vargs);
}

struct _store_check_cachable_hist {

    struct {
        int non_get;
        int not_entry_cachable;
        int wrong_content_length;
        int too_big;
        int too_small;
        int private_key;
        int too_many_open_files;
        int too_many_open_fds;
        int missing_parts;
    } no;

    struct {
        int Default;
    } yes;
} store_check_cachable_hist;

int
storeTooManyDiskFilesOpen(void)
{
    if (Config.max_open_disk_fds == 0)
        return 0;

    if (store_open_disk_fd > Config.max_open_disk_fds)
        return 1;

    return 0;
}

int
StoreEntry::checkTooSmall()
{
    if (EBIT_TEST(flags, ENTRY_SPECIAL))
        return 0;

    if (STORE_OK == store_status)
        if (mem_obj->object_sz >= 0 &&
                mem_obj->object_sz < Config.Store.minObjectSize)
            return 1;

    const auto clen = mem().baseReply().content_length;
    if (clen >= 0 && clen < Config.Store.minObjectSize)
        return 1;
    return 0;
}

bool
StoreEntry::checkTooBig() const
{
    if (mem_obj->endOffset() > store_maxobjsize)
        return true;

    const auto clen = mem_obj->baseReply().content_length;
    return (clen >= 0 && clen > store_maxobjsize);
}

// TODO: move "too many open..." checks outside -- we are called too early/late
bool
StoreEntry::checkCachable()
{
    // XXX: This method is used for both memory and disk caches, but some
    // checks are specific to disk caches. Move them to mayStartSwapOut().

    // XXX: This method may be called several times, sometimes with different
    // outcomes, making store_check_cachable_hist counters misleading.

    // check this first to optimize handling of repeated calls for uncachables
    if (EBIT_TEST(flags, RELEASE_REQUEST)) {
        debugs(20, 2, "StoreEntry::checkCachable: NO: not cachable");
        ++store_check_cachable_hist.no.not_entry_cachable; // TODO: rename?
        return 0; // avoid rerequesting release below
    }

#if CACHE_ALL_METHODS

    if (mem_obj->method != Http::METHOD_GET) {
        debugs(20, 2, "StoreEntry::checkCachable: NO: non-GET method");
        ++store_check_cachable_hist.no.non_get;
    } else
#endif
        if (store_status == STORE_OK && EBIT_TEST(flags, ENTRY_BAD_LENGTH)) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: wrong content-length");
            ++store_check_cachable_hist.no.wrong_content_length;
        } else if (!mem_obj) {
            // XXX: In bug 4131, we forgetHit() without mem_obj, so we need
            // this segfault protection, but how can we get such a HIT?
            debugs(20, 2, "StoreEntry::checkCachable: NO: missing parts: " << *this);
            ++store_check_cachable_hist.no.missing_parts;
        } else if (checkTooBig()) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too big");
            ++store_check_cachable_hist.no.too_big;
        } else if (checkTooSmall()) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too small");
            ++store_check_cachable_hist.no.too_small;
        } else if (EBIT_TEST(flags, KEY_PRIVATE)) {
            debugs(20, 3, "StoreEntry::checkCachable: NO: private key");
            ++store_check_cachable_hist.no.private_key;
        } else if (hasDisk()) {
            /*
             * the remaining cases are only relevant if we haven't
             * started swapping out the object yet.
             */
            return 1;
        } else if (storeTooManyDiskFilesOpen()) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too many disk files open");
            ++store_check_cachable_hist.no.too_many_open_files;
        } else if (fdNFree() < RESERVED_FD) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too many FD's open");
            ++store_check_cachable_hist.no.too_many_open_fds;
        } else {
            ++store_check_cachable_hist.yes.Default;
            return 1;
        }

    releaseRequest();
    return 0;
}

void
storeCheckCachableStats(StoreEntry *sentry)
{
    storeAppendPrintf(sentry, "Category\t Count\n");

#if CACHE_ALL_METHODS

    storeAppendPrintf(sentry, "no.non_get\t%d\n",
                      store_check_cachable_hist.no.non_get);
#endif

    storeAppendPrintf(sentry, "no.not_entry_cachable\t%d\n",
                      store_check_cachable_hist.no.not_entry_cachable);
    storeAppendPrintf(sentry, "no.wrong_content_length\t%d\n",
                      store_check_cachable_hist.no.wrong_content_length);
    storeAppendPrintf(sentry, "no.negative_cached\t%d\n",
                      0); // TODO: Remove this backward compatibility hack.
    storeAppendPrintf(sentry, "no.missing_parts\t%d\n",
                      store_check_cachable_hist.no.missing_parts);
    storeAppendPrintf(sentry, "no.too_big\t%d\n",
                      store_check_cachable_hist.no.too_big);
    storeAppendPrintf(sentry, "no.too_small\t%d\n",
                      store_check_cachable_hist.no.too_small);
    storeAppendPrintf(sentry, "no.private_key\t%d\n",
                      store_check_cachable_hist.no.private_key);
    storeAppendPrintf(sentry, "no.too_many_open_files\t%d\n",
                      store_check_cachable_hist.no.too_many_open_files);
    storeAppendPrintf(sentry, "no.too_many_open_fds\t%d\n",
                      store_check_cachable_hist.no.too_many_open_fds);
    storeAppendPrintf(sentry, "yes.default\t%d\n",
                      store_check_cachable_hist.yes.Default);
}

void
StoreEntry::lengthWentBad(const char *reason)
{
    debugs(20, 3, "because " << reason << ": " << *this);
    EBIT_SET(flags, ENTRY_BAD_LENGTH);
    releaseRequest();
}

void
StoreEntry::complete()
{
    debugs(20, 3, "storeComplete: '" << getMD5Text() << "'");

    // To preserve forwarding retries, call FwdState::complete() instead.
    EBIT_CLR(flags, ENTRY_FWD_HDR_WAIT);

    if (store_status != STORE_PENDING) {
        /*
         * if we're not STORE_PENDING, then probably we got aborted
         * and there should be NO clients on this entry
         */
        assert(EBIT_TEST(flags, ENTRY_ABORTED));
        assert(mem_obj->nclients == 0);
        return;
    }

    mem_obj->object_sz = mem_obj->endOffset();

    store_status = STORE_OK;

    assert(mem_status == NOT_IN_MEMORY);

    if (!EBIT_TEST(flags, ENTRY_BAD_LENGTH) && !validLength())
        lengthWentBad("!validLength() in complete()");

#if USE_CACHE_DIGESTS
    if (mem_obj->request)
        mem_obj->request->hier.store_complete_stop = current_time;

#endif
    /*
     * We used to call invokeHandlers, then storeSwapOut.  However,
     * Madhukar Reddy <myreddy@persistence.com> reported that
     * responses without content length would sometimes get released
     * in client_side, thinking that the response is incomplete.
     */
    invokeHandlers();
}

/*
 * Someone wants to abort this transfer.  Set the reason in the
 * request structure, call the callback and mark the
 * entry for releasing
 */
void
StoreEntry::abort()
{
    ++statCounter.aborted_requests;
    assert(store_status == STORE_PENDING);
    assert(mem_obj != NULL);
    debugs(20, 6, "storeAbort: " << getMD5Text());

    lock("StoreEntry::abort");         /* lock while aborting */
    negativeCache();

    releaseRequest();

    EBIT_SET(flags, ENTRY_ABORTED);

    // allow the Store clients to be told about the problem
    EBIT_CLR(flags, ENTRY_FWD_HDR_WAIT);

    setMemStatus(NOT_IN_MEMORY);

    store_status = STORE_OK;

    /* Notify the server side */

    /*
     * DPW 2007-05-07
     * Should we check abort.data for validity?
     */
    if (mem_obj->abort.callback) {
        if (!cbdataReferenceValid(mem_obj->abort.data))
            debugs(20, DBG_IMPORTANT,HERE << "queueing event when abort.data is not valid");
        eventAdd("mem_obj->abort.callback",
                 mem_obj->abort.callback,
                 mem_obj->abort.data,
                 0.0,
                 true);
        unregisterAbort();
    }

    /* XXX Should we reverse these two, so that there is no
     * unneeded disk swapping triggered?
     */
    /* Notify the client side */
    invokeHandlers();

    // abort swap out, invalidating what was created so far (release follows)
    swapOutFileClose(StoreIOState::writerGone);

    unlock("StoreEntry::abort");       /* unlock */
}

/**
 * Clear Memory storage to accommodate the given object len
 */
void
storeGetMemSpace(int size)
{
    PROF_start(storeGetMemSpace);
    if (!shutting_down) // Store::Root() is FATALly missing during shutdown
        Store::Root().freeMemorySpace(size);
    PROF_stop(storeGetMemSpace);
}

/* thunk through to Store::Root().maintain(). Note that this would be better still
 * if registered against the root store itself, but that requires more complex
 * update logic - bigger fish to fry first. Long term each store when
 * it becomes active will self register
 */
void
Store::Maintain(void *)
{
    Store::Root().maintain();

    /* Reregister a maintain event .. */
    eventAdd("MaintainSwapSpace", Maintain, NULL, 1.0, 1);

}

/* The maximum objects to scan for maintain storage space */
#define MAINTAIN_MAX_SCAN       1024
#define MAINTAIN_MAX_REMOVE     64

void
StoreEntry::release(const bool shareable)
{
    PROF_start(storeRelease);
    debugs(20, 3, shareable << ' ' << *this << ' ' << getMD5Text());
    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */

    if (locked()) {
        releaseRequest(shareable);
        PROF_stop(storeRelease);
        return;
    }

    if (Store::Controller::store_dirs_rebuilding && hasDisk()) {
        /* TODO: Teach disk stores to handle releases during rebuild instead. */

        // lock the entry until rebuilding is done
        lock("storeLateRelease");
        releaseRequest(shareable);
        LateReleaseStack.push(this);
        PROF_stop(storeRelease);
        return;
    }

    storeLog(STORE_LOG_RELEASE, this);
    Store::Root().evictCached(*this);
    destroyStoreEntry(static_cast<hash_link *>(this));
    PROF_stop(storeRelease);
}

static void
storeLateRelease(void *)
{
    StoreEntry *e;
    static int n = 0;

    if (Store::Controller::store_dirs_rebuilding) {
        eventAdd("storeLateRelease", storeLateRelease, NULL, 1.0, 1);
        return;
    }

    // TODO: this works but looks unelegant.
    for (int i = 0; i < 10; ++i) {
        if (LateReleaseStack.empty()) {
            debugs(20, DBG_IMPORTANT, "storeLateRelease: released " << n << " objects");
            return;
        } else {
            e = LateReleaseStack.top();
            LateReleaseStack.pop();
        }

        e->unlock("storeLateRelease");
        ++n;
    }

    eventAdd("storeLateRelease", storeLateRelease, NULL, 0.0, 1);
}

/// whether the base response has all the body bytes we expect
/// \returns true for responses with unknown/unspecified body length
/// \returns true for responses with the right number of accumulated body bytes
bool
StoreEntry::validLength() const
{
    int64_t diff;
    assert(mem_obj != NULL);
    const auto reply = &mem_obj->baseReply();
    debugs(20, 3, "storeEntryValidLength: Checking '" << getMD5Text() << "'");
    debugs(20, 5, "storeEntryValidLength:     object_len = " <<
           objectLen());
    debugs(20, 5, "storeEntryValidLength:         hdr_sz = " << reply->hdr_sz);
    debugs(20, 5, "storeEntryValidLength: content_length = " << reply->content_length);

    if (reply->content_length < 0) {
        debugs(20, 5, "storeEntryValidLength: Unspecified content length: " << getMD5Text());
        return 1;
    }

    if (reply->hdr_sz == 0) {
        debugs(20, 5, "storeEntryValidLength: Zero header size: " << getMD5Text());
        return 1;
    }

    if (mem_obj->method == Http::METHOD_HEAD) {
        debugs(20, 5, "storeEntryValidLength: HEAD request: " << getMD5Text());
        return 1;
    }

    if (reply->sline.status() == Http::scNotModified)
        return 1;

    if (reply->sline.status() == Http::scNoContent)
        return 1;

    diff = reply->hdr_sz + reply->content_length - objectLen();

    if (diff == 0)
        return 1;

    debugs(20, 3, "storeEntryValidLength: " << (diff < 0 ? -diff : diff)  << " bytes too " << (diff < 0 ? "big" : "small") <<"; '" << getMD5Text() << "'" );

    return 0;
}

static void
storeRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("storedir", "Store Directory Stats", Store::Stats, 0, 1);
    Mgr::RegisterAction("store_io", "Store IO Interface Stats", &Mgr::StoreIoAction::Create, 0, 1);
    Mgr::RegisterAction("store_check_cachable_stats", "storeCheckCachable() Stats",
                        storeCheckCachableStats, 0, 1);
}

void
storeInit(void)
{
    storeKeyInit();
    mem_policy = createRemovalPolicy(Config.memPolicy);
    storeDigestInit();
    storeLogOpen();
    eventAdd("storeLateRelease", storeLateRelease, NULL, 1.0, 1);
    Store::Root().init();
    storeRebuildStart();

    storeRegisterWithCacheManager();
}

void
storeConfigure(void)
{
    Store::Root().updateLimits();
}

bool
StoreEntry::memoryCachable()
{
    if (!checkCachable())
        return 0;

    if (mem_obj == NULL)
        return 0;

    if (mem_obj->data_hdr.size() == 0)
        return 0;

    if (mem_obj->inmem_lo != 0)
        return 0;

    if (!Config.onoff.memory_cache_first && swappedOut() && refcount == 1)
        return 0;

    return 1;
}

int
StoreEntry::checkNegativeHit() const
{
    if (!EBIT_TEST(flags, ENTRY_NEGCACHED))
        return 0;

    if (expires <= squid_curtime)
        return 0;

    if (store_status != STORE_OK)
        return 0;

    return 1;
}

/**
 * Set object for negative caching.
 * Preserves any expiry information given by the server.
 * In absence of proper expiry info it will set to expire immediately,
 * or with HTTP-violations enabled the configured negative-TTL is observed
 */
void
StoreEntry::negativeCache()
{
    // XXX: should make the default for expires 0 instead of -1
    //      so we can distinguish "Expires: -1" from nothing.
    if (expires <= 0)
#if USE_HTTP_VIOLATIONS
        expires = squid_curtime + Config.negativeTtl;
#else
        expires = squid_curtime;
#endif
    if (expires > squid_curtime) {
        EBIT_SET(flags, ENTRY_NEGCACHED);
        debugs(20, 6, "expires = " << expires << " +" << (expires-squid_curtime) << ' ' << *this);
    }
}

void
storeFreeMemory(void)
{
    Store::FreeMemory();
#if USE_CACHE_DIGESTS
    delete store_digest;
#endif
    store_digest = NULL;
}

int
expiresMoreThan(time_t expires, time_t when)
{
    if (expires < 0)            /* No Expires given */
        return 1;

    return (expires > (squid_curtime + when));
}

int
StoreEntry::validToSend() const
{
    if (EBIT_TEST(flags, RELEASE_REQUEST))
        return 0;

    if (EBIT_TEST(flags, ENTRY_NEGCACHED))
        if (expires <= squid_curtime)
            return 0;

    if (EBIT_TEST(flags, ENTRY_ABORTED))
        return 0;

    // now check that the entry has a cache backing or is collapsed
    if (hasDisk()) // backed by a disk cache
        return 1;

    if (swappingOut()) // will be backed by a disk cache
        return 1;

    if (!mem_obj) // not backed by a memory cache and not collapsed
        return 0;

    // StoreEntry::storeClientType() assumes DISK_CLIENT here, but there is no
    // disk cache backing that store_client constructor will assert. XXX: This
    // is wrong for range requests (that could feed off nibbled memory) and for
    // entries backed by the shared memory cache (that could, in theory, get
    // nibbled bytes from that cache, but there is no such "memoryIn" code).
    if (mem_obj->inmem_lo) // in memory cache, but got nibbled at
        return 0;

    // The following check is correct but useless at this position. TODO: Move
    // it up when the shared memory cache can either replenish locally nibbled
    // bytes or, better, does not use local RAM copy at all.
    // if (mem_obj->memCache.index >= 0) // backed by a shared memory cache
    //    return 1;

    return 1;
}

bool
StoreEntry::timestampsSet()
{
    debugs(20, 7, *this << " had " << describeTimestamps());

    // TODO: Remove change-reducing "&" before the official commit.
    const auto reply = &mem().freshestReply();

    time_t served_date = reply->date;
    int age = reply->header.getInt(Http::HdrType::AGE);
    /* Compute the timestamp, mimicking RFC2616 section 13.2.3. */
    /* make sure that 0 <= served_date <= squid_curtime */

    if (served_date < 0 || served_date > squid_curtime)
        served_date = squid_curtime;

    /* Bug 1791:
     * If the returned Date: is more than 24 hours older than
     * the squid_curtime, then one of us needs to use NTP to set our
     * clock.  We'll pretend that our clock is right.
     */
    else if (served_date < (squid_curtime - 24 * 60 * 60) )
        served_date = squid_curtime;

    /*
     * Compensate with Age header if origin server clock is ahead
     * of us and there is a cache in between us and the origin
     * server.  But DONT compensate if the age value is larger than
     * squid_curtime because it results in a negative served_date.
     */
    if (age > squid_curtime - served_date)
        if (squid_curtime > age)
            served_date = squid_curtime - age;

    // compensate for Squid-to-server and server-to-Squid delays
    if (mem_obj && mem_obj->request) {
        struct timeval responseTime;
        if (mem_obj->request->hier.peerResponseTime(responseTime))
            served_date -= responseTime.tv_sec;
    }

    time_t exp = 0;
    if (reply->expires > 0 && reply->date > -1)
        exp = served_date + (reply->expires - reply->date);
    else
        exp = reply->expires;

    if (timestamp == served_date && expires == exp) {
        // if the reply lacks LMT, then we now know that our effective
        // LMT (i.e., timestamp) will stay the same, otherwise, old and
        // new modification times must match
        if (reply->last_modified < 0 || reply->last_modified == lastModified())
            return false; // nothing has changed
    }

    expires = exp;

    lastModified_ = reply->last_modified;

    timestamp = served_date;

    debugs(20, 5, *this << " has " << describeTimestamps());
    return true;
}

bool
StoreEntry::updateOnNotModified(const StoreEntry &e304)
{
    assert(mem_obj);
    assert(e304.mem_obj);

    // update reply before calling timestampsSet() below
    const auto &oldReply = mem_obj->freshestReply();
    const auto updatedReply = oldReply.recreateOnNotModified(e304.mem_obj->baseReply());
    if (updatedReply) // HTTP 304 brought in new information
        mem_obj->updateReply(*updatedReply);
    // else continue to use the previous update, if any

    if (!timestampsSet() && !updatedReply)
        return false;

    // Keep the old mem_obj->vary_headers; see HttpHeader::skipUpdateHeader().

    debugs(20, 5, "updated basics in " << *this << " with " << e304);
    mem_obj->appliedUpdates = true; // helps in triage; may already be true
    return true;
}

void
StoreEntry::registerAbort(STABH * cb, void *data)
{
    assert(mem_obj);
    assert(mem_obj->abort.callback == NULL);
    mem_obj->abort.callback = cb;
    mem_obj->abort.data = cbdataReference(data);
}

void
StoreEntry::unregisterAbort()
{
    assert(mem_obj);
    if (mem_obj->abort.callback) {
        mem_obj->abort.callback = NULL;
        cbdataReferenceDone(mem_obj->abort.data);
    }
}

void
StoreEntry::dump(int l) const
{
    debugs(20, l, "StoreEntry->key: " << getMD5Text());
    debugs(20, l, "StoreEntry->next: " << next);
    debugs(20, l, "StoreEntry->mem_obj: " << mem_obj);
    debugs(20, l, "StoreEntry->timestamp: " << timestamp);
    debugs(20, l, "StoreEntry->lastref: " << lastref);
    debugs(20, l, "StoreEntry->expires: " << expires);
    debugs(20, l, "StoreEntry->lastModified_: " << lastModified_);
    debugs(20, l, "StoreEntry->swap_file_sz: " << swap_file_sz);
    debugs(20, l, "StoreEntry->refcount: " << refcount);
    debugs(20, l, "StoreEntry->flags: " << storeEntryFlags(this));
    debugs(20, l, "StoreEntry->swap_dirn: " << swap_dirn);
    debugs(20, l, "StoreEntry->swap_filen: " << swap_filen);
    debugs(20, l, "StoreEntry->lock_count: " << lock_count);
    debugs(20, l, "StoreEntry->mem_status: " << mem_status);
    debugs(20, l, "StoreEntry->ping_status: " << ping_status);
    debugs(20, l, "StoreEntry->store_status: " << store_status);
    debugs(20, l, "StoreEntry->swap_status: " << swap_status);
}

/*
 * NOTE, this function assumes only two mem states
 */
void
StoreEntry::setMemStatus(mem_status_t new_status)
{
    if (new_status == mem_status)
        return;

    // are we using a shared memory cache?
    if (MemStore::Enabled()) {
        // This method was designed to update replacement policy, not to
        // actually purge something from the memory cache (TODO: rename?).
        // Shared memory cache does not have a policy that needs updates.
        mem_status = new_status;
        return;
    }

    assert(mem_obj != NULL);

    if (new_status == IN_MEMORY) {
        assert(mem_obj->inmem_lo == 0);

        if (EBIT_TEST(flags, ENTRY_SPECIAL)) {
            debugs(20, 4, "not inserting special " << *this << " into policy");
        } else {
            mem_policy->Add(mem_policy, this, &mem_obj->repl);
            debugs(20, 4, "inserted " << *this << " key: " << getMD5Text());
        }

        ++hot_obj_count; // TODO: maintain for the shared hot cache as well
    } else {
        if (EBIT_TEST(flags, ENTRY_SPECIAL)) {
            debugs(20, 4, "not removing special " << *this << " from policy");
        } else {
            mem_policy->Remove(mem_policy, this, &mem_obj->repl);
            debugs(20, 4, "removed " << *this);
        }

        --hot_obj_count;
    }

    mem_status = new_status;
}

const char *
StoreEntry::url() const
{
    if (mem_obj == NULL)
        return "[null_mem_obj]";
    else
        return mem_obj->storeId();
}

void
StoreEntry::createMemObject()
{
    assert(!mem_obj);
    mem_obj = new MemObject();
}

void
StoreEntry::createMemObject(const char *aUrl, const char *aLogUrl, const HttpRequestMethod &aMethod)
{
    assert(!mem_obj);
    ensureMemObject(aUrl, aLogUrl, aMethod);
}

void
StoreEntry::ensureMemObject(const char *aUrl, const char *aLogUrl, const HttpRequestMethod &aMethod)
{
    if (!mem_obj)
        mem_obj = new MemObject();
    mem_obj->setUris(aUrl, aLogUrl, aMethod);
}

/** disable sending content to the clients.
 *
 * This just sets DELAY_SENDING.
 */
void
StoreEntry::buffer()
{
    EBIT_SET(flags, DELAY_SENDING);
}

/** flush any buffered content.
 *
 * This just clears DELAY_SENDING and Invokes the handlers
 * to begin sending anything that may be buffered.
 */
void
StoreEntry::flush()
{
    if (EBIT_TEST(flags, DELAY_SENDING)) {
        EBIT_CLR(flags, DELAY_SENDING);
        invokeHandlers();
    }
}

void
StoreEntry::reset()
{
    debugs(20, 3, url());
    mem().reset();
    expires = lastModified_ = timestamp = -1;
}

/*
 * storeFsInit
 *
 * This routine calls the SETUP routine for each fs type.
 * I don't know where the best place for this is, and I'm not going to shuffle
 * around large chunks of code right now (that can be done once its working.)
 */
void
storeFsInit(void)
{
    storeReplSetup();
}

/*
 * called to add another store removal policy module
 */
void
storeReplAdd(const char *type, REMOVALPOLICYCREATE * create)
{
    int i;

    /* find the number of currently known repl types */
    for (i = 0; storerepl_list && storerepl_list[i].typestr; ++i) {
        if (strcmp(storerepl_list[i].typestr, type) == 0) {
            debugs(20, DBG_IMPORTANT, "WARNING: Trying to load store replacement policy " << type << " twice.");
            return;
        }
    }

    /* add the new type */
    storerepl_list = static_cast<storerepl_entry_t *>(xrealloc(storerepl_list, (i + 2) * sizeof(storerepl_entry_t)));

    memset(&storerepl_list[i + 1], 0, sizeof(storerepl_entry_t));

    storerepl_list[i].typestr = type;

    storerepl_list[i].create = create;
}

/*
 * Create a removal policy instance
 */
RemovalPolicy *
createRemovalPolicy(RemovalPolicySettings * settings)
{
    storerepl_entry_t *r;

    for (r = storerepl_list; r && r->typestr; ++r) {
        if (strcmp(r->typestr, settings->type) == 0)
            return r->create(settings->args);
    }

    debugs(20, DBG_IMPORTANT, "ERROR: Unknown policy " << settings->type);
    debugs(20, DBG_IMPORTANT, "ERROR: Be sure to have set cache_replacement_policy");
    debugs(20, DBG_IMPORTANT, "ERROR:   and memory_replacement_policy in squid.conf!");
    fatalf("ERROR: Unknown policy %s\n", settings->type);
    return NULL;                /* NOTREACHED */
}

#if 0
void
storeSwapFileNumberSet(StoreEntry * e, sfileno filn)
{
    if (e->swap_file_number == filn)
        return;

    if (filn < 0) {
        assert(-1 == filn);
        storeDirMapBitReset(e->swap_file_number);
        storeDirLRUDelete(e);
        e->swap_file_number = -1;
    } else {
        assert(-1 == e->swap_file_number);
        storeDirMapBitSet(e->swap_file_number = filn);
        storeDirLRUAdd(e);
    }
}

#endif

void
StoreEntry::storeErrorResponse(HttpReply *reply)
{
    lock("StoreEntry::storeErrorResponse");
    buffer();
    replaceHttpReply(HttpReplyPointer(reply));
    flush();
    complete();
    negativeCache();
    releaseRequest(false); // if it is safe to negatively cache, sharing is OK
    unlock("StoreEntry::storeErrorResponse");
}

/*
 * Replace a store entry with
 * a new reply. This eats the reply.
 */
void
StoreEntry::replaceHttpReply(const HttpReplyPointer &rep, const bool andStartWriting)
{
    debugs(20, 3, "StoreEntry::replaceHttpReply: " << url());

    if (!mem_obj) {
        debugs(20, DBG_CRITICAL, "Attempt to replace object with no in-memory representation");
        return;
    }

    mem_obj->replaceBaseReply(rep);

    if (andStartWriting)
        startWriting();
}

void
StoreEntry::startWriting()
{
    /* TODO: when we store headers separately remove the header portion */
    /* TODO: mark the length of the headers ? */
    /* We ONLY want the headers */
    assert (isEmpty());
    assert(mem_obj);

    // Per MemObject replies definitions, we can only write our base reply.
    // Currently, all callers replaceHttpReply() first, so there is no updated
    // reply here anyway. Eventually, we may need to support the
    // updateOnNotModified(),startWriting() sequence as well.
    assert(!mem_obj->updatedReply());
    const auto rep = &mem_obj->baseReply();

    buffer();
    rep->packHeadersUsingSlowPacker(*this);
    mem_obj->markEndOfReplyHeaders();

    rep->body.packInto(this);
    flush();

    // The entry headers are written, new clients
    // should not collapse anymore.
    if (hittingRequiresCollapsing()) {
        setCollapsingRequirement(false);
        Store::Root().transientsClearCollapsingRequirement(*this);
    }
}

char const *
StoreEntry::getSerialisedMetaData(size_t &length) const
{
    StoreMeta *tlv_list = storeSwapMetaBuild(this);
    int swap_hdr_sz;
    char *result = storeSwapMetaPack(tlv_list, &swap_hdr_sz);
    storeSwapTLVFree(tlv_list);
    assert (swap_hdr_sz >= 0);
    length = static_cast<size_t>(swap_hdr_sz);
    return result;
}

/**
 * Abandon the transient entry our worker has created if neither the shared
 * memory cache nor the disk cache wants to store it. Collapsed requests, if
 * any, should notice and use Plan B instead of getting stuck waiting for us
 * to start swapping the entry out.
 */
void
StoreEntry::transientsAbandonmentCheck()
{
    if (mem_obj && !Store::Root().transientsReader(*this) && // this worker is responsible
            hasTransients() && // other workers may be interested
            !hasMemStore() && // rejected by the shared memory cache
            mem_obj->swapout.decision == MemObject::SwapOut::swImpossible) {
        debugs(20, 7, "cannot be shared: " << *this);
        if (!shutting_down) // Store::Root() is FATALly missing during shutdown
            Store::Root().stopSharing(*this);
    }
}

void
StoreEntry::memOutDecision(const bool)
{
    transientsAbandonmentCheck();
}

void
StoreEntry::swapOutDecision(const MemObject::SwapOut::Decision &decision)
{
    // Abandon our transient entry if neither shared memory nor disk wants it.
    assert(mem_obj);
    mem_obj->swapout.decision = decision;
    transientsAbandonmentCheck();
}

void
StoreEntry::trimMemory(const bool preserveSwappable)
{
    /*
     * DPW 2007-05-09
     * Bug #1943.  We must not let go any data for IN_MEMORY
     * objects.  We have to wait until the mem_status changes.
     */
    if (mem_status == IN_MEMORY)
        return;

    if (EBIT_TEST(flags, ENTRY_SPECIAL))
        return; // cannot trim because we do not load them again

    if (preserveSwappable)
        mem_obj->trimSwappable();
    else
        mem_obj->trimUnSwappable();

    debugs(88, 7, *this << " inmem_lo=" << mem_obj->inmem_lo);
}

bool
StoreEntry::modifiedSince(const time_t ims, const int imslen) const
{
    const time_t mod_time = lastModified();

    debugs(88, 3, "modifiedSince: '" << url() << "'");

    debugs(88, 3, "modifiedSince: mod_time = " << mod_time);

    if (mod_time < 0)
        return true;

    assert(imslen < 0); // TODO: Either remove imslen or support it properly.

    if (mod_time > ims) {
        debugs(88, 3, "--> YES: entry newer than client");
        return true;
    } else if (mod_time < ims) {
        debugs(88, 3, "-->  NO: entry older than client");
        return false;
    } else {
        debugs(88, 3, "-->  NO: same LMT");
        return false;
    }
}

bool
StoreEntry::hasEtag(ETag &etag) const
{
    if (const auto reply = hasFreshestReply()) {
        etag = reply->header.getETag(Http::HdrType::ETAG);
        if (etag.str)
            return true;
    }
    return false;
}

bool
StoreEntry::hasIfMatchEtag(const HttpRequest &request) const
{
    const String reqETags = request.header.getList(Http::HdrType::IF_MATCH);
    return hasOneOfEtags(reqETags, false);
}

bool
StoreEntry::hasIfNoneMatchEtag(const HttpRequest &request) const
{
    const String reqETags = request.header.getList(Http::HdrType::IF_NONE_MATCH);
    // weak comparison is allowed only for HEAD or full-body GET requests
    const bool allowWeakMatch = !request.flags.isRanged &&
                                (request.method == Http::METHOD_GET || request.method == Http::METHOD_HEAD);
    return hasOneOfEtags(reqETags, allowWeakMatch);
}

/// whether at least one of the request ETags matches entity ETag
bool
StoreEntry::hasOneOfEtags(const String &reqETags, const bool allowWeakMatch) const
{
    const auto repETag = mem().freshestReply().header.getETag(Http::HdrType::ETAG);
    if (!repETag.str) {
        static SBuf asterisk("*", 1);
        return strListIsMember(&reqETags, asterisk, ',');
    }

    bool matched = false;
    const char *pos = NULL;
    const char *item;
    int ilen;
    while (!matched && strListGetItem(&reqETags, ',', &item, &ilen, &pos)) {
        if (!strncmp(item, "*", ilen))
            matched = true;
        else {
            String str;
            str.append(item, ilen);
            ETag reqETag;
            if (etagParseInit(&reqETag, str.termedBuf())) {
                matched = allowWeakMatch ? etagIsWeakEqual(repETag, reqETag) :
                          etagIsStrongEqual(repETag, reqETag);
            }
        }
    }
    return matched;
}

Store::Disk &
StoreEntry::disk() const
{
    assert(hasDisk());
    const RefCount<Store::Disk> &sd = INDEXSD(swap_dirn);
    assert(sd);
    return *sd;
}

bool
StoreEntry::hasDisk(const sdirno dirn, const sfileno filen) const
{
    checkDisk();
    if (dirn < 0 && filen < 0)
        return swap_dirn >= 0;
    Must(dirn >= 0);
    const bool matchingDisk = (swap_dirn == dirn);
    return filen < 0 ? matchingDisk : (matchingDisk && swap_filen == filen);
}

void
StoreEntry::attachToDisk(const sdirno dirn, const sfileno fno, const swap_status_t status)
{
    debugs(88, 3, "attaching entry with key " << getMD5Text() << " : " <<
           swapStatusStr[status] << " " << dirn << " " <<
           std::hex << std::setw(8) << std::setfill('0') <<
           std::uppercase << fno);
    checkDisk();
    swap_dirn = dirn;
    swap_filen = fno;
    swap_status = status;
    checkDisk();
}

void
StoreEntry::detachFromDisk()
{
    swap_dirn = -1;
    swap_filen = -1;
    swap_status = SWAPOUT_NONE;
}

void
StoreEntry::checkDisk() const
{
    try {
        if (swap_dirn < 0) {
            Must(swap_filen < 0);
            Must(swap_status == SWAPOUT_NONE);
        } else {
            Must(swap_filen >= 0);
            Must(swap_dirn < Config.cacheSwap.n_configured);
            if (swapoutFailed()) {
                Must(EBIT_TEST(flags, RELEASE_REQUEST));
            } else {
                Must(swappingOut() || swappedOut());
            }
        }
    } catch (...) {
        debugs(88, DBG_IMPORTANT, "ERROR: inconsistent disk entry state " <<
               *this << "; problem: " << CurrentException);
        throw;
    }
}

/*
 * return true if the entry is in a state where
 * it can accept more data (ie with write() method)
 */
bool
StoreEntry::isAccepting() const
{
    if (STORE_PENDING != store_status)
        return false;

    if (EBIT_TEST(flags, ENTRY_ABORTED))
        return false;

    return true;
}

const char *
StoreEntry::describeTimestamps() const
{
    LOCAL_ARRAY(char, buf, 256);
    snprintf(buf, 256, "LV:%-9d LU:%-9d LM:%-9d EX:%-9d",
             static_cast<int>(timestamp),
             static_cast<int>(lastref),
             static_cast<int>(lastModified_),
             static_cast<int>(expires));
    return buf;
}

void
StoreEntry::setCollapsingRequirement(const bool required)
{
    if (required)
        EBIT_SET(flags, ENTRY_REQUIRES_COLLAPSING);
    else
        EBIT_CLR(flags, ENTRY_REQUIRES_COLLAPSING);
}

static std::ostream &
operator <<(std::ostream &os, const Store::IoStatus &io)
{
    switch (io) {
    case Store::ioUndecided:
        os << 'u';
        break;
    case Store::ioReading:
        os << 'r';
        break;
    case Store::ioWriting:
        os << 'w';
        break;
    case Store::ioDone:
        os << 'o';
        break;
    }
    return os;
}

std::ostream &operator <<(std::ostream &os, const StoreEntry &e)
{
    os << "e:";

    if (e.hasTransients()) {
        const auto &xitTable = e.mem_obj->xitTable;
        os << 't' << xitTable.io << xitTable.index;
    }

    if (e.hasMemStore()) {
        const auto &memCache = e.mem_obj->memCache;
        os << 'm' << memCache.io << memCache.index << '@' << memCache.offset;
    }

    // Do not use e.hasDisk() here because its checkDisk() call may calls us.
    if (e.swap_filen > -1 || e.swap_dirn > -1)
        os << 'd' << e.swap_filen << '@' << e.swap_dirn;

    os << '=';

    // print only non-default status values, using unique letters
    if (e.mem_status != NOT_IN_MEMORY ||
            e.store_status != STORE_PENDING ||
            e.swap_status != SWAPOUT_NONE ||
            e.ping_status != PING_NONE) {
        if (e.mem_status != NOT_IN_MEMORY) os << 'm';
        if (e.store_status != STORE_PENDING) os << 's';
        if (e.swap_status != SWAPOUT_NONE) os << 'w' << e.swap_status;
        if (e.ping_status != PING_NONE) os << 'p' << e.ping_status;
    }

    // print only set flags, using unique letters
    if (e.flags) {
        if (EBIT_TEST(e.flags, ENTRY_SPECIAL)) os << 'S';
        if (EBIT_TEST(e.flags, ENTRY_REVALIDATE_ALWAYS)) os << 'R';
        if (EBIT_TEST(e.flags, DELAY_SENDING)) os << 'P';
        if (EBIT_TEST(e.flags, RELEASE_REQUEST)) os << 'X';
        if (EBIT_TEST(e.flags, REFRESH_REQUEST)) os << 'F';
        if (EBIT_TEST(e.flags, ENTRY_REVALIDATE_STALE)) os << 'E';
        if (EBIT_TEST(e.flags, KEY_PRIVATE)) {
            os << 'I';
            if (e.shareableWhenPrivate)
                os << 'H';
        }
        if (EBIT_TEST(e.flags, ENTRY_FWD_HDR_WAIT)) os << 'W';
        if (EBIT_TEST(e.flags, ENTRY_NEGCACHED)) os << 'N';
        if (EBIT_TEST(e.flags, ENTRY_VALIDATED)) os << 'V';
        if (EBIT_TEST(e.flags, ENTRY_BAD_LENGTH)) os << 'L';
        if (EBIT_TEST(e.flags, ENTRY_ABORTED)) os << 'A';
        if (EBIT_TEST(e.flags, ENTRY_REQUIRES_COLLAPSING)) os << 'C';
    }

    return os << '/' << &e << '*' << e.locks();
}

void
Store::EntryGuard::onException() noexcept
{
    SWALLOW_EXCEPTIONS({
        entry_->releaseRequest(false);
        entry_->unlock(context_);
    });
}

