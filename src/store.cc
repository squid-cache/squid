
/*
 * $Id$
 *
 * DEBUG: section 20    Storage Manager
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "event.h"
#include "Store.h"
#include "CacheManager.h"
#include "StoreClient.h"
#include "stmem.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "mem_node.h"
#include "StoreMeta.h"
#include "SwapDir.h"
#if DELAY_POOLS
#include "DelayPools.h"
#endif
#include "Stack.h"
#include "SquidTime.h"

static STMCB storeWriteComplete;

#define REBUILD_TIMESTAMP_DELTA_MAX 2

#define STORE_IN_MEM_BUCKETS            (229)

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
    "SWAPOUT_DONE"
};

extern OBJH storeIOStats;


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
static void storeGetMemSpace(int);
static int getKeyCounter(void);
static OBJH storeCheckCachableStats;
static EVH storeLateRelease;

/*
 * local variables
 */
static Stack<StoreEntry*> LateReleaseStack;
MemAllocator *StoreEntry::pool = NULL;

StorePointer Store::CurrentRoot = NULL;

void
Store::Root(Store * aRoot)
{
    CurrentRoot = aRoot;
}

void
Store::Root(StorePointer aRoot)
{
    Root(aRoot.getRaw());
}

void
Store::Stats(StoreEntry * output)
{
    assert (output);
    Root().stat(*output);
}

void
Store::create()
{}

void
Store::diskFull()
{}

void
Store::sync()
{}

void
Store::unlink (StoreEntry &anEntry)
{
    fatal("Store::unlink on invalid Store\n");
}

void *
StoreEntry::operator new (size_t bytecount)
{
    assert (bytecount == sizeof (StoreEntry));

    if (!pool) {
        pool = memPoolCreate ("StoreEntry", bytecount);
        pool->setChunkSize(2048 * 1024);
    }

    return pool->alloc();
}

void
StoreEntry::operator delete (void *address)
{
    pool->free(address);
}

void
StoreEntry::makePublic()
{
    /* This object can be cached for a long time */

    if (EBIT_TEST(flags, ENTRY_CACHABLE))
        setPublicKey();
}

void
StoreEntry::makePrivate()
{
    /* This object should never be cached at all */
    expireNow();
    releaseRequest(); /* delete object when not used */
    /* releaseRequest clears ENTRY_CACHABLE flag */
}

void
StoreEntry::cacheNegatively()
{
    /* This object may be negatively cached */
    negativeCache();

    if (EBIT_TEST(flags, ENTRY_CACHABLE))
        setPublicKey();
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
    anEntry->delayAwareRead(aRead.fd,
                            aRead.buf,
                            aRead.len,
                            aRead.callback);
}

void
StoreEntry::delayAwareRead(int fd, char *buf, int len, AsyncCall::Pointer callback)
{
    size_t amountToRead = bytesWanted(Range<size_t>(0, len));
    /* sketch: readdeferer* = getdeferer.
     * ->deferRead (fd, buf, len, callback, DelayAwareRead, this)
     */

    if (amountToRead == 0) {
        assert (mem_obj);
        /* read ahead limit */
        /* Perhaps these two calls should both live in MemObject */
#if DELAY_POOLS

        if (!mem_obj->readAheadPolicyCanRead()) {
#endif
            mem_obj->delayRead(DeferredRead(DeferReader, this, CommRead(fd, buf, len, callback)));
            return;
#if DELAY_POOLS

        }

        /* delay id limit */
        mem_obj->mostBytesAllowed().delayRead(DeferredRead(DeferReader, this, CommRead(fd, buf, len, callback)));

        return;

#endif

    }

    comm_read(fd, buf, amountToRead, callback);
}

size_t
StoreEntry::bytesWanted (Range<size_t> const aRange) const
{
    assert (aRange.size());

    if (mem_obj == NULL)
        return aRange.end - 1;

#if URL_CHECKSUM_DEBUG

    mem_obj->checkUrlChecksum();

#endif

    /* Always read *something* here - we haven't got the header yet */
    if (EBIT_TEST(flags, ENTRY_FWD_HDR_WAIT))
        return aRange.end - 1;

    if (!mem_obj->readAheadPolicyCanRead())
        return 0;

    return mem_obj->mostBytesWanted(aRange.end - 1);
}

bool
StoreEntry::checkDeferRead(int fd) const
{
    return (bytesWanted(Range<size_t>(0,INT_MAX)) == 0);
}

void
StoreEntry::setNoDelay (bool const newValue)
{
    if (mem_obj)
        mem_obj->setNoDelay(newValue);
}

store_client_t
StoreEntry::storeClientType() const
{
    /* The needed offset isn't in memory
     * XXX TODO: this is wrong for range requests
     * as the needed offset may *not* be 0, AND
     * offset 0 in the memory object is the HTTP headers.
     */

    if (mem_obj->inmem_lo)
        return STORE_DISK_CLIENT;

    if (EBIT_TEST(flags, ENTRY_ABORTED)) {
        /* I don't think we should be adding clients to aborted entries */
        debugs(20, 1, "storeClientType: adding to ENTRY_ABORTED entry");
        return STORE_MEM_CLIENT;
    }

    if (store_status == STORE_OK) {
        /* the object has completed. */

        if (mem_obj->inmem_lo == 0 && !isEmpty())
            /* hot object */
            return STORE_MEM_CLIENT;
        else
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

StoreEntry::StoreEntry()
{
    debugs(20, 3, HERE << "new StoreEntry " << this);
    mem_obj = NULL;

    expires = lastmod = lastref = timestamp = -1;

    swap_filen = -1;
    swap_dirn = -1;
}

StoreEntry::StoreEntry(const char *aUrl, const char *aLogUrl)
{
    debugs(20, 3, HERE << "new StoreEntry " << this);
    mem_obj = new MemObject(aUrl, aLogUrl);

    expires = lastmod = lastref = timestamp = -1;

    swap_filen = -1;
    swap_dirn = -1;
}

void
StoreEntry::destroyMemObject()
{
    debugs(20, 3, HERE << "destroyMemObject " << mem_obj);
    setMemStatus(NOT_IN_MEMORY);
    MemObject *mem = mem_obj;
    mem_obj = NULL;
    delete mem;
}

void
destroyStoreEntry(void *data)
{
    debugs(20, 3, HERE << "destroyStoreEntry: destroying " <<  data);
    StoreEntry *e = static_cast<StoreEntry *>(static_cast<hash_link *>(data));
    assert(e != NULL);

    if (e == NullStoreEntry::getInstance())
        return;

    e->destroyMemObject();

    e->hashDelete();

    assert(e->key == NULL);

    delete e;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

void
StoreEntry::hashInsert(const cache_key * someKey)
{
    debugs(20, 3, "StoreEntry::hashInsert: Inserting Entry " << this << " key '" << storeKeyText(someKey) << "'");
    key = storeKeyDup(someKey);
    hash_join(store_table, this);
}

void
StoreEntry::hashDelete()
{
    hash_remove_link(store_table, this);
    storeKeyFree((const cache_key *)key);
    key = NULL;
}

/* -------------------------------------------------------------------------- */


/* get rid of memory copy of the object */
void
StoreEntry::purgeMem()
{
    if (mem_obj == NULL)
        return;

    debugs(20, 3, "StoreEntry::purgeMem: Freeing memory-copy of " << getMD5Text());

    destroyMemObject();

    if (swap_status != SWAPOUT_DONE)
        release();
}

/* RBC 20050104 this is wrong- memory ref counting
 * is not at all equivalent to the store 'usage' concept
 * which the replacement policies should be acting upon.
 * specifically, object iteration within stores needs
 * memory ref counting to prevent race conditions,
 * but this should not influence store replacement.
 */
void

StoreEntry::lock()
{
    lock_count++;
    debugs(20, 3, "StoreEntry::lock: key '" << getMD5Text() <<"' count=" <<
           lock_count  );
    lastref = squid_curtime;
    Store::Root().reference(*this);
}

void
StoreEntry::setReleaseFlag()
{
    if (EBIT_TEST(flags, RELEASE_REQUEST))
        return;

    debugs(20, 3, "StoreEntry::setReleaseFlag: '" << getMD5Text() << "'");

    EBIT_SET(flags, RELEASE_REQUEST);
}

void
StoreEntry::releaseRequest()
{
    if (EBIT_TEST(flags, RELEASE_REQUEST))
        return;

    setReleaseFlag();

    /*
     * Clear cachable flag here because we might get called before
     * anyone else even looks at the cachability flag.  Also, this
     * prevents httpMakePublic from really setting a public key.
     */
    EBIT_CLR(flags, ENTRY_CACHABLE);

    setPrivateKey();
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */
int
StoreEntry::unlock()
{
    lock_count--;
    debugs(20, 3, "StoreEntry::unlock: key '" << getMD5Text() << "' count=" << lock_count);

    if (lock_count)
        return (int) lock_count;

    if (store_status == STORE_PENDING)
        setReleaseFlag();

    assert(storePendingNClients(this) == 0);

    if (EBIT_TEST(flags, RELEASE_REQUEST))
        this->release();
    else if (keepInMemory()) {
        Store::Root().dereference(*this);
        setMemStatus(IN_MEMORY);
        mem_obj->unlinkRequest();
    } else {
        Store::Root().dereference(*this);

        if (EBIT_TEST(flags, KEY_PRIVATE))
            debugs(20, 1, "WARNING: " << __FILE__ << ":" << __LINE__ << ": found KEY_PRIVATE");

        /* StoreEntry::purgeMem may free e */
        purgeMem();
    }

    return 0;
}

void
StoreEntry::getPublicByRequestMethod  (StoreClient *aClient, HttpRequest * request, const HttpRequestMethod& method)
{
    assert (aClient);
    StoreEntry *result = storeGetPublicByRequestMethod( request, method);

    if (!result)
        aClient->created (NullStoreEntry::getInstance());
    else
        aClient->created (result);
}

void
StoreEntry::getPublicByRequest (StoreClient *aClient, HttpRequest * request)
{
    assert (aClient);
    StoreEntry *result = storeGetPublicByRequest (request);

    if (!result)
        result = NullStoreEntry::getInstance();

    aClient->created (result);
}

void
StoreEntry::getPublic (StoreClient *aClient, const char *uri, const HttpRequestMethod& method)
{
    assert (aClient);
    StoreEntry *result = storeGetPublic (uri, method);

    if (!result)
        result = NullStoreEntry::getInstance();

    aClient->created (result);
}

StoreEntry *
storeGetPublic(const char *uri, const HttpRequestMethod& method)
{
    return Store::Root().get(storeKeyPublic(uri, method));
}

StoreEntry *
storeGetPublicByRequestMethod(HttpRequest * req, const HttpRequestMethod& method)
{
    return Store::Root().get(storeKeyPublicByRequestMethod(req, method));
}

StoreEntry *
storeGetPublicByRequest(HttpRequest * req)
{
    StoreEntry *e = storeGetPublicByRequestMethod(req, req->method);

    if (e == NULL && req->method == METHOD_HEAD)
        /* We can generate a HEAD reply from a cached GET object */
        e = storeGetPublicByRequestMethod(req, METHOD_GET);

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
StoreEntry::setPrivateKey()
{
    const cache_key *newkey;

    if (key && EBIT_TEST(flags, KEY_PRIVATE))
        return;                 /* is already private */

    if (key) {
        if (swap_filen > -1)
            storeDirSwapLog(this, SWAP_LOG_DEL);

        hashDelete();
    }

    if (mem_obj != NULL) {
        mem_obj->id = getKeyCounter();
        newkey = storeKeyPrivate(mem_obj->url, mem_obj->method, mem_obj->id);
    } else {
        newkey = storeKeyPrivate("JUNK", METHOD_NONE, getKeyCounter());
    }

    assert(hash_lookup(store_table, newkey) == NULL);
    EBIT_SET(flags, KEY_PRIVATE);
    hashInsert(newkey);
}

void
StoreEntry::setPublicKey()
{
    StoreEntry *e2 = NULL;
    const cache_key *newkey;

    if (key && !EBIT_TEST(flags, KEY_PRIVATE))
        return;                 /* is already public */

    assert(mem_obj);

    /*
     * We can't make RELEASE_REQUEST objects public.  Depending on
     * when RELEASE_REQUEST gets set, we might not be swapping out
     * the object.  If we're not swapping out, then subsequent
     * store clients won't be able to access object data which has
     * been freed from memory.
     *
     * If RELEASE_REQUEST is set, then ENTRY_CACHABLE should not
     * be set, and StoreEntry::setPublicKey() should not be called.
     */
#if MORE_DEBUG_OUTPUT

    if (EBIT_TEST(flags, RELEASE_REQUEST))
        debugs(20, 1, "assertion failed: RELEASE key " << key << ", url " << mem_obj->url);

#endif

    assert(!EBIT_TEST(flags, RELEASE_REQUEST));

    if (mem_obj->request) {
        HttpRequest *request = mem_obj->request;

        if (!mem_obj->vary_headers) {
            /* First handle the case where the object no longer varies */
            safe_free(request->vary_headers);
        } else {
            if (request->vary_headers && strcmp(request->vary_headers, mem_obj->vary_headers) != 0) {
                /* Oops.. the variance has changed. Kill the base object
                 * to record the new variance key
                 */
                safe_free(request->vary_headers);       /* free old "bad" variance key */
                StoreEntry *pe = storeGetPublic(mem_obj->url, mem_obj->method);

                if (pe)
                    pe->release();
            }

            /* Make sure the request knows the variance status */
            if (!request->vary_headers) {
                const char *vary = httpMakeVaryMark(request, mem_obj->getReply());

                if (vary)
                    request->vary_headers = xstrdup(vary);
            }
        }

        if (mem_obj->vary_headers && !storeGetPublic(mem_obj->url, mem_obj->method)) {
            /* Create "vary" base object */
            String vary;
            StoreEntry *pe = storeCreateEntry(mem_obj->url, mem_obj->log_url, request->flags, request->method);
            /* We are allowed to do this typecast */
            HttpReply *rep = new HttpReply;
            rep->setHeaders(HTTP_OK, "Internal marker object", "x-squid-internal/vary", -1, -1, squid_curtime + 100000);
            vary = mem_obj->getReply()->header.getList(HDR_VARY);

            if (vary.size()) {
                /* Again, we own this structure layout */
                rep->header.putStr(HDR_VARY, vary.termedBuf());
                vary.clean();
            }

#if X_ACCELERATOR_VARY
            vary = mem_obj->getReply()->header.getList(HDR_X_ACCELERATOR_VARY);

            if (vary.defined()) {
                /* Again, we own this structure layout */
                rep->header.putStr(HDR_X_ACCELERATOR_VARY, vary.termedBuf());
                vary.clean();
            }

#endif
            pe->replaceHttpReply(rep);

            pe->timestampsSet();

            pe->makePublic();

            pe->complete();

            pe->unlock();
        }

        newkey = storeKeyPublicByRequest(mem_obj->request);
    } else
        newkey = storeKeyPublic(mem_obj->url, mem_obj->method);

    if ((e2 = (StoreEntry *) hash_lookup(store_table, newkey))) {
        debugs(20, 3, "StoreEntry::setPublicKey: Making old '" << mem_obj->url << "' private.");
        e2->setPrivateKey();
        e2->release();

        if (mem_obj->request)
            newkey = storeKeyPublicByRequest(mem_obj->request);
        else
            newkey = storeKeyPublic(mem_obj->url, mem_obj->method);
    }

    if (key)
        hashDelete();

    EBIT_CLR(flags, KEY_PRIVATE);

    hashInsert(newkey);

    if (swap_filen > -1)
        storeDirSwapLog(this, SWAP_LOG_ADD);
}

StoreEntry *
storeCreateEntry(const char *url, const char *log_url, request_flags flags, const HttpRequestMethod& method)
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    debugs(20, 3, "storeCreateEntry: '" << url << "'");

    e = new StoreEntry(url, log_url);
    e->lock_count = 1;          /* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    mem->method = method;

    if (neighbors_do_private_keys || !flags.hierarchical)
        e->setPrivateKey();
    else
        e->setPublicKey();

    if (flags.cachable) {
        EBIT_SET(e->flags, ENTRY_CACHABLE);
        EBIT_CLR(e->flags, RELEASE_REQUEST);
    } else {
        /* StoreEntry::releaseRequest() clears ENTRY_CACHABLE */
        e->releaseRequest();
    }

    e->store_status = STORE_PENDING;
    e->setMemStatus(NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_NONE;
    e->swap_filen = -1;
    e->swap_dirn = -1;
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = -1;          /* set in StoreEntry::timestampsSet() */
    e->ping_status = PING_NONE;
    EBIT_SET(e->flags, ENTRY_VALIDATED);
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
storeWriteComplete (void *data, StoreIOBuffer wroteBuffer)
{
    PROF_start(storeWriteComplete);
    StoreEntry *e = (StoreEntry *)data;

    if (EBIT_TEST(e->flags, DELAY_SENDING)) {
        PROF_stop(storeWriteComplete);
        return;
    }

    e->invokeHandlers();
    PROF_stop(storeWriteComplete);
}

void
StoreEntry::write (StoreIOBuffer writeBuffer)
{
    assert(mem_obj != NULL);
    assert(writeBuffer.length >= 0);
    /* This assert will change when we teach the store to update */
    PROF_start(StoreEntry_write);
    assert(store_status == STORE_PENDING);

    if (!writeBuffer.length) {
        /* the headers are received already, but we have not received
         * any body data. There are BROKEN abuses of HTTP which require
         * the headers to be passed along before any body data - see
         * http://developer.apple.com/documentation/QuickTime/QTSS/Concepts/chapter_2_section_14.html
         * for an example of such bad behaviour. To accomodate this, if
         * we have a empty write arrive, we flush to our clients.
         * -RBC 20060903
         */
        PROF_stop(StoreEntry_write);
        invokeHandlers();
        return;
    }

    debugs(20, 5, "storeWrite: writing " << writeBuffer.length << " bytes for '" << getMD5Text() << "'");
    PROF_stop(StoreEntry_write);
    storeGetMemSpace(writeBuffer.length);
    mem_obj->write (writeBuffer, storeWriteComplete, this);
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
    tempBuffer.offset = mem_obj->endOffset() - (getReply() ? getReply()->hdr_sz : 0);
    write(tempBuffer);
}


void
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);

    storeAppendVPrintf(e, fmt, args);
    va_end(args);
}

/* used be storeAppendPrintf and Packer */
void
storeAppendVPrintf(StoreEntry * e, const char *fmt, va_list vargs)
{
    LOCAL_ARRAY(char, buf, 4096);
    buf[0] = '\0';
    vsnprintf(buf, 4096, fmt, vargs);
    e->append(buf, strlen(buf));
}

struct _store_check_cachable_hist {

    struct {
        int non_get;
        int not_entry_cachable;
        int wrong_content_length;
        int negative_cached;
        int too_big;
        int too_small;
        int private_key;
        int too_many_open_files;
        int too_many_open_fds;
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
        if (mem_obj->object_sz < 0 ||
                mem_obj->object_sz < Config.Store.minObjectSize)
            return 1;
    if (getReply()->content_length > -1)
        if (getReply()->content_length < Config.Store.minObjectSize)
            return 1;
    return 0;
}

int
StoreEntry::checkCachable()
{
#if CACHE_ALL_METHODS

    if (mem_obj->method != METHOD_GET) {
        debugs(20, 2, "StoreEntry::checkCachable: NO: non-GET method");
        store_check_cachable_hist.no.non_get++;
    } else
#endif
        if (store_status == STORE_OK && EBIT_TEST(flags, ENTRY_BAD_LENGTH)) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: wrong content-length");
            store_check_cachable_hist.no.wrong_content_length++;
        } else if (!EBIT_TEST(flags, ENTRY_CACHABLE)) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: not cachable");
            store_check_cachable_hist.no.not_entry_cachable++;
        } else if (EBIT_TEST(flags, ENTRY_NEGCACHED)) {
            debugs(20, 3, "StoreEntry::checkCachable: NO: negative cached");
            store_check_cachable_hist.no.negative_cached++;
            return 0;           /* avoid release call below */
        } else if ((getReply()->content_length > 0 &&
                    getReply()->content_length
                    > Config.Store.maxObjectSize) ||
                   mem_obj->endOffset() > Config.Store.maxObjectSize) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too big");
            store_check_cachable_hist.no.too_big++;
        } else if (getReply()->content_length > Config.Store.maxObjectSize) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too big");
            store_check_cachable_hist.no.too_big++;
        } else if (checkTooSmall()) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too small");
            store_check_cachable_hist.no.too_small++;
        } else if (EBIT_TEST(flags, KEY_PRIVATE)) {
            debugs(20, 3, "StoreEntry::checkCachable: NO: private key");
            store_check_cachable_hist.no.private_key++;
        } else if (swap_status != SWAPOUT_NONE) {
            /*
             * here we checked the swap_status because the remaining
             * cases are only relevant only if we haven't started swapping
             * out the object yet.
             */
            return 1;
        } else if (storeTooManyDiskFilesOpen()) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too many disk files open");
            store_check_cachable_hist.no.too_many_open_files++;
        } else if (fdNFree() < RESERVED_FD) {
            debugs(20, 2, "StoreEntry::checkCachable: NO: too many FD's open");
            store_check_cachable_hist.no.too_many_open_fds++;
        } else {
            store_check_cachable_hist.yes.Default++;
            return 1;
        }

    releaseRequest();
    /* StoreEntry::releaseRequest() cleared ENTRY_CACHABLE */
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
                      store_check_cachable_hist.no.negative_cached);
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
StoreEntry::complete()
{
    debugs(20, 3, "storeComplete: '" << getMD5Text() << "'");

    if (store_status != STORE_PENDING) {
        /*
         * if we're not STORE_PENDING, then probably we got aborted
         * and there should be NO clients on this entry
         */
        assert(EBIT_TEST(flags, ENTRY_ABORTED));
        assert(mem_obj->nclients == 0);
        return;
    }

    /* This is suspect: mem obj offsets include the headers. do we adjust for that
     * in use of object_sz?
     */
    mem_obj->object_sz = mem_obj->endOffset();

    store_status = STORE_OK;

    assert(mem_status == NOT_IN_MEMORY);

    if (!validLength()) {
        EBIT_SET(flags, ENTRY_BAD_LENGTH);
        releaseRequest();
    }

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
 * request structure, call the server-side callback and mark the
 * entry for releasing
 */
void
StoreEntry::abort()
{
    statCounter.aborted_requests++;
    assert(store_status == STORE_PENDING);
    assert(mem_obj != NULL);
    debugs(20, 6, "storeAbort: " << getMD5Text());

    lock();         /* lock while aborting */
    negativeCache();

    releaseRequest();

    EBIT_SET(flags, ENTRY_ABORTED);

    setMemStatus(NOT_IN_MEMORY);

    store_status = STORE_OK;

    /*
     * We assign an object length here.  The only other place we assign
     * the object length is in storeComplete()
     */
    /* RBC: What do we need an object length for? we've just aborted the
     * request, the request is private and negatively cached. Surely
     * the object length is inappropriate to set.
     */
    mem_obj->object_sz = mem_obj->endOffset();

    /* Notify the server side */

    /*
     * DPW 2007-05-07
     * Should we check abort.data for validity?
     */
    if (mem_obj->abort.callback) {
        if (!cbdataReferenceValid(mem_obj->abort.data))
            debugs(20,1,HERE << "queueing event when abort.data is not valid");
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

    /* Close any swapout file */
    swapOutFileClose();

    unlock();       /* unlock */
}

/* Clear Memory storage to accommodate the given object len */
static void
storeGetMemSpace(int size)
{
    PROF_start(storeGetMemSpace);
    StoreEntry *e = NULL;
    int released = 0;
    static time_t last_check = 0;
    size_t pages_needed;
    RemovalPurgeWalker *walker;

    if (squid_curtime == last_check) {
        PROF_stop(storeGetMemSpace);
        return;
    }

    last_check = squid_curtime;

    pages_needed = (size / SM_PAGE_SIZE) + 1;

    if (mem_node::InUseCount() + pages_needed < store_pages_max) {
        PROF_stop(storeGetMemSpace);
        return;
    }

    debugs(20, 2, "storeGetMemSpace: Starting, need " << pages_needed <<
           " pages");

    /* XXX what to set as max_scan here? */
    walker = mem_policy->PurgeInit(mem_policy, 100000);

    while ((e = walker->Next(walker))) {
        e->purgeMem();
        released++;

        if (mem_node::InUseCount() + pages_needed < store_pages_max)
            break;
    }

    walker->Done(walker);
    debugs(20, 3, "storeGetMemSpace stats:");
    debugs(20, 3, "  " << std::setw(6) << hot_obj_count  << " HOT objects");
    debugs(20, 3, "  " << std::setw(6) << released  << " were released");
    PROF_stop(storeGetMemSpace);
}


/* thunk through to Store::Root().maintain(). Note that this would be better still
 * if registered against the root store itself, but that requires more complex
 * update logic - bigger fish to fry first. Long term each store when
 * it becomes active will self register
 */
void
Store::Maintain(void *notused)
{
    Store::Root().maintain();

    /* Reregister a maintain event .. */
    eventAdd("MaintainSwapSpace", Maintain, NULL, 1.0, 1);

}

/* The maximum objects to scan for maintain storage space */
#define MAINTAIN_MAX_SCAN       1024
#define MAINTAIN_MAX_REMOVE     64

/*
 * This routine is to be called by main loop in main.c.
 * It removes expired objects on only one bucket for each time called.
 *
 * This should get called 1/s from main().
 */
void
StoreController::maintain()
{
    static time_t last_warn_time = 0;

    PROF_start(storeMaintainSwapSpace);
    swapDir->maintain();

    /* this should be emitted by the oversize dir, not globally */

    if (store_swap_size > Store::Root().maxSize()) {
        if (squid_curtime - last_warn_time > 10) {
            debugs(20, 0, "WARNING: Disk space over limit: " << store_swap_size << " KB > "
                   << Store::Root().maxSize() << " KB");
            last_warn_time = squid_curtime;
        }
    }

    PROF_stop(storeMaintainSwapSpace);
}

/* release an object from a cache */
void
StoreEntry::release()
{
    PROF_start(storeRelease);
    debugs(20, 3, "storeRelease: Releasing: '" << getMD5Text() << "'");
    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */

    if (locked()) {
        expireNow();
        debugs(20, 3, "storeRelease: Only setting RELEASE_REQUEST bit");
        releaseRequest();
        PROF_stop(storeRelease);
        return;
    }

    if (StoreController::store_dirs_rebuilding && swap_filen > -1) {
        setPrivateKey();

        if (mem_obj)
            destroyMemObject();

        if (swap_filen > -1) {
            /*
             * Fake a call to StoreEntry->lock()  When rebuilding is done,
             * we'll just call StoreEntry->unlock() on these.
             */
            lock_count++;
            setReleaseFlag();
            LateReleaseStack.push_back(this);
            PROF_stop(storeRelease);
            return;
        } else {
            destroyStoreEntry(static_cast<hash_link *>(this));
        }
    }

    storeLog(STORE_LOG_RELEASE, this);

    if (swap_filen > -1) {
        unlink();

        if (swap_status == SWAPOUT_DONE)
            if (EBIT_TEST(flags, ENTRY_VALIDATED))
                store()->updateSize(swap_file_sz, -1);

        if (!EBIT_TEST(flags, KEY_PRIVATE))
            storeDirSwapLog(this, SWAP_LOG_DEL);

#if 0
        /* From 2.4. I think we do this in storeUnlink? */
        storeSwapFileNumberSet(this, -1);

#endif

    }

    setMemStatus(NOT_IN_MEMORY);
    destroyStoreEntry(static_cast<hash_link *>(this));
    PROF_stop(storeRelease);
}

static void
storeLateRelease(void *unused)
{
    StoreEntry *e;
    int i;
    static int n = 0;

    if (StoreController::store_dirs_rebuilding) {
        eventAdd("storeLateRelease", storeLateRelease, NULL, 1.0, 1);
        return;
    }

    for (i = 0; i < 10; i++) {
        e = LateReleaseStack.pop();

        if (e == NULL) {
            /* done! */
            debugs(20, 1, "storeLateRelease: released " << n << " objects");
            return;
        }

        e->unlock();
        n++;
    }

    eventAdd("storeLateRelease", storeLateRelease, NULL, 0.0, 1);
}

/* return 1 if a store entry is locked */
int
StoreEntry::locked() const
{
    if (lock_count)
        return 1;

    if (swap_status == SWAPOUT_WRITING)
        return 1;

    if (store_status == STORE_PENDING)
        return 1;

    /*
     * SPECIAL, PUBLIC entries should be "locked"
     */
    if (EBIT_TEST(flags, ENTRY_SPECIAL))
        if (!EBIT_TEST(flags, KEY_PRIVATE))
            return 1;

    return 0;
}

bool
StoreEntry::validLength() const
{
    int64_t diff;
    const HttpReply *reply;
    assert(mem_obj != NULL);
    reply = getReply();
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

    if (mem_obj->method == METHOD_HEAD) {
        debugs(20, 5, "storeEntryValidLength: HEAD request: " << getMD5Text());
        return 1;
    }

    if (reply->sline.status == HTTP_NOT_MODIFIED)
        return 1;

    if (reply->sline.status == HTTP_NO_CONTENT)
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
    CacheManager *manager=CacheManager::GetInstance();
    manager->registerAction("storedir", "Store Directory Stats", Store::Stats, 0, 1);
    manager->registerAction("store_io", "Store IO Interface Stats", storeIOStats, 0, 1);
    manager->registerAction("store_check_cachable_stats", "storeCheckCachable() Stats",
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
    store_swap_high = (long) (((float) Store::Root().maxSize() *
                               (float) Config.Swap.highWaterMark) / (float) 100);
    store_swap_low = (long) (((float) Store::Root().maxSize() *
                              (float) Config.Swap.lowWaterMark) / (float) 100);
    store_pages_max = Config.memMaxSize / sizeof(mem_node);
}

int
StoreEntry::keepInMemory() const
{
    if (mem_obj == NULL)
        return 0;

    if (mem_obj->data_hdr.size() == 0)
        return 0;

    return mem_obj->inmem_lo == 0;
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
    if (expires == 0)
#if HTTP_VIOLATIONS
        expires = squid_curtime + Config.negativeTtl;
#else
        expires = squid_curtime;
#endif
    EBIT_SET(flags, ENTRY_NEGCACHED);
}

void
storeFreeMemory(void)
{
    Store::Root(NULL);
#if USE_CACHE_DIGESTS

    if (store_digest)
        cacheDigestDestroy(store_digest);

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

    return 1;
}

void
StoreEntry::timestampsSet()
{
    const HttpReply *reply = getReply();
    time_t served_date = reply->date;
    int age = reply->header.getInt(HDR_AGE);
    /* Compute the timestamp, mimicking RFC2616 section 13.2.3. */
    /* make sure that 0 <= served_date <= squid_curtime */

    if (served_date < 0 || served_date > squid_curtime)
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
        const time_t request_sent =
            mem_obj->request->hier.peer_http_request_sent.tv_sec;
        if (0 < request_sent && request_sent < squid_curtime)
            served_date -= (squid_curtime - request_sent);
    }

    if (reply->expires > 0 && reply->date > -1)
        expires = served_date + (reply->expires - reply->date);
    else
        expires = reply->expires;

    lastmod = reply->last_modified;

    timestamp = served_date;
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
    debugs(20, l, "StoreEntry->lastmod: " << lastmod);
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

    assert(mem_obj != NULL);

    if (new_status == IN_MEMORY) {
        assert(mem_obj->inmem_lo == 0);

        if (EBIT_TEST(flags, ENTRY_SPECIAL)) {
            debugs(20, 4, "StoreEntry::setMemStatus: not inserting special " << mem_obj->url << " into policy");
        } else {
            mem_policy->Add(mem_policy, this, &mem_obj->repl);
            debugs(20, 4, "StoreEntry::setMemStatus: inserted mem node " << mem_obj->url);
        }

        hot_obj_count++;
    } else {
        if (EBIT_TEST(flags, ENTRY_SPECIAL)) {
            debugs(20, 4, "StoreEntry::setMemStatus: special entry " << mem_obj->url);
        } else {
            mem_policy->Remove(mem_policy, this, &mem_obj->repl);
            debugs(20, 4, "StoreEntry::setMemStatus: removed mem node " << mem_obj->url);
        }

        hot_obj_count--;
    }

    mem_status = new_status;
}

const char *
StoreEntry::url() const
{
    if (this == NULL)
        return "[null_entry]";
    else if (mem_obj == NULL)
        return "[null_mem_obj]";
    else
        return mem_obj->url;
}

void
StoreEntry::createMemObject(const char *aUrl, const char *aLogUrl)
{
    if (mem_obj)
        return;

    mem_obj = new MemObject(aUrl, aLogUrl);
}

/* this just sets DELAY_SENDING */
void
StoreEntry::buffer()
{
    EBIT_SET(flags, DELAY_SENDING);
}

/* this just clears DELAY_SENDING and Invokes the handlers */
void
StoreEntry::flush()
{
    if (EBIT_TEST(flags, DELAY_SENDING)) {
        EBIT_CLR(flags, DELAY_SENDING);
        invokeHandlers();
    }
}

int64_t
StoreEntry::objectLen() const
{
    assert(mem_obj != NULL);
    return mem_obj->object_sz;
}

int64_t
StoreEntry::contentLen() const
{
    assert(mem_obj != NULL);
    assert(getReply() != NULL);
    return objectLen() - getReply()->hdr_sz;
}

HttpReply const *
StoreEntry::getReply () const
{
    if (NULL == mem_obj)
        return NULL;

    return mem_obj->getReply();
}

void
StoreEntry::reset()
{
    assert (mem_obj);
    debugs(20, 3, "StoreEntry::reset: " << url());
    mem_obj->reset();
    HttpReply *rep = (HttpReply *) getReply();       // bypass const
    rep->reset();
    expires = lastmod = timestamp = -1;
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

    for (i = 0; storerepl_list && storerepl_list[i].typestr; i++) {
        assert(strcmp(storerepl_list[i].typestr, type) != 0);
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

    for (r = storerepl_list; r && r->typestr; r++) {
        if (strcmp(r->typestr, settings->type) == 0)
            return r->create(settings->args);
    }

    debugs(20, 1, "ERROR: Unknown policy " << settings->type);
    debugs(20, 1, "ERROR: Be sure to have set cache_replacement_policy");
    debugs(20, 1, "ERROR:   and memory_replacement_policy in squid.conf!");
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


/*
 * Replace a store entry with
 * a new reply. This eats the reply.
 */
void
StoreEntry::replaceHttpReply(HttpReply *rep)
{
    debugs(20, 3, "StoreEntry::replaceHttpReply: " << url());
    Packer p;

    if (!mem_obj) {
        debugs(20, 0, "Attempt to replace object with no in-memory representation");
        return;
    }

    mem_obj->replaceHttpReply(rep);

    /* TODO: when we store headers serparately remove the header portion */
    /* TODO: mark the length of the headers ? */
    /* We ONLY want the headers */
    packerToStoreInit(&p, this);

    assert (isEmpty());

    getReply()->packHeadersInto(&p);

    rep->hdr_sz = mem_obj->endOffset();

    httpBodyPackInto(&getReply()->body, &p);

    packerClean(&p);
}


char const *
StoreEntry::getSerialisedMetaData()
{
    StoreMeta *tlv_list = storeSwapMetaBuild(this);
    int swap_hdr_sz;
    char *result = storeSwapMetaPack(tlv_list, &swap_hdr_sz);
    storeSwapTLVFree(tlv_list);
    assert (swap_hdr_sz >= 0);
    mem_obj->swap_hdr_sz = (size_t) swap_hdr_sz;
    return result;
}

bool
StoreEntry::swapoutPossible()
{
    /* should we swap something out to disk? */
    debugs(20, 7, "storeSwapOut: " << url());
    debugs(20, 7, "storeSwapOut: store_status = " << storeStatusStr[store_status]);

    if (EBIT_TEST(flags, ENTRY_ABORTED)) {
        assert(EBIT_TEST(flags, RELEASE_REQUEST));
        swapOutFileClose();
        return false;
    }

    if (EBIT_TEST(flags, ENTRY_SPECIAL)) {
        debugs(20, 3, "storeSwapOut: " << url() << " SPECIAL");
        return false;
    }

    return true;
}

void
StoreEntry::trimMemory()
{
    /*
     * DPW 2007-05-09
     * Bug #1943.  We must not let go any data for IN_MEMORY
     * objects.  We have to wait until the mem_status changes.
     */
    if (mem_status == IN_MEMORY)
        return;

    if (mem_obj->policyLowestOffsetToKeep() == 0)
        /* Nothing to do */
        return;

    if (!swapOutAble()) {
        /*
         * Its not swap-able, and we're about to delete a chunk,
         * so we must make it PRIVATE.  This is tricky/ugly because
         * for the most part, we treat swapable == cachable here.
         */
        releaseRequest();
        mem_obj->trimUnSwappable ();
    } else {
        mem_obj->trimSwappable ();
    }
}

bool
StoreEntry::modifiedSince(HttpRequest * request) const
{
    int object_length;
    time_t mod_time = lastmod;

    if (mod_time < 0)
        mod_time = timestamp;

    debugs(88, 3, "modifiedSince: '" << url() << "'");

    debugs(88, 3, "modifiedSince: mod_time = " << mod_time);

    if (mod_time < 0)
        return true;

    /* Find size of the object */
    object_length = getReply()->content_length;

    if (object_length < 0)
        object_length = contentLen();

    if (mod_time > request->ims) {
        debugs(88, 3, "--> YES: entry newer than client");
        return true;
    } else if (mod_time < request->ims) {
        debugs(88, 3, "-->  NO: entry older than client");
        return false;
    } else if (request->imslen < 0) {
        debugs(88, 3, "-->  NO: same LMT, no client length");
        return false;
    } else if (request->imslen == object_length) {
        debugs(88, 3, "-->  NO: same LMT, same length");
        return false;
    } else {
        debugs(88, 3, "--> YES: same LMT, different length");
        return true;
    }
}

bool
StoreEntry::hasIfMatchEtag(const HttpRequest &request) const
{
    const String reqETags = request.header.getList(HDR_IF_MATCH);
    return hasOneOfEtags(reqETags, false);
}

bool
StoreEntry::hasIfNoneMatchEtag(const HttpRequest &request) const
{
    const String reqETags = request.header.getList(HDR_IF_NONE_MATCH);
    // weak comparison is allowed only for HEAD or full-body GET requests
    const bool allowWeakMatch = !request.flags.range &&
                                (request.method == METHOD_GET || request.method == METHOD_HEAD);
    return hasOneOfEtags(reqETags, allowWeakMatch);
}

/// whether at least one of the request ETags matches entity ETag
bool
StoreEntry::hasOneOfEtags(const String &reqETags, const bool allowWeakMatch) const
{
    const ETag repETag = getReply()->header.getETag(HDR_ETAG);
    if (!repETag.str)
        return strListIsMember(&reqETags, "*", ',');

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

StorePointer
StoreEntry::store() const
{
    assert(0 <= swap_dirn && swap_dirn < Config.cacheSwap.n_configured);
    return INDEXSD(swap_dirn);
}

void
StoreEntry::unlink()
{
    store()->unlink(*this);
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

/* NullStoreEntry */

NullStoreEntry NullStoreEntry::_instance;

NullStoreEntry *
NullStoreEntry::getInstance()
{
    return &_instance;
}

char const *
NullStoreEntry::getMD5Text() const
{
    return "N/A";
}

void
NullStoreEntry::operator delete(void*)
{
    fatal ("Attempt to delete NullStoreEntry\n");
}

char const *
NullStoreEntry::getSerialisedMetaData()
{
    return NULL;
}

#ifndef _USE_INLINE_
#include "Store.cci"
#endif
