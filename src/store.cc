
/*
 * $Id: store.cc,v 1.575 2003/09/25 00:06:56 wessels Exp $
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
#include "Store.h"
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

static STMCB storeWriteComplete;

#define REBUILD_TIMESTAMP_DELTA_MAX 2

#define STORE_IN_MEM_BUCKETS		(229)

const char *memStatusStr[] =
    {
        "NOT_IN_MEMORY",
        "IN_MEMORY"
    };

const char *pingStatusStr[] =
    {
        "PING_NONE",
        "PING_WAITING",
        "PING_DONE"
    };

const char *storeStatusStr[] =
    {
        "STORE_OK",
        "STORE_PENDING"
    };

const char *swapStatusStr[] =
    {
        "SWAPOUT_NONE",
        "SWAPOUT_WRITING",
        "SWAPOUT_DONE"
    };

typedef struct lock_ctrl_t
{
    SIH *callback;
    void *callback_data;
    StoreEntry *e;
}

lock_ctrl_t;

extern OBJH storeIOStats;

/*
 * local function prototypes
 */
static void storeGetMemSpace(int);
static void storeHashDelete(StoreEntry *);
static void destroy_MemObject(StoreEntry *);
static FREE destroyStoreEntry;
static void storePurgeMem(StoreEntry *);
static void storeEntryReferenced(StoreEntry *);
static void storeEntryDereferenced(StoreEntry *);
static int getKeyCounter(void);
static int storeKeepInMemory(const StoreEntry *);
static OBJH storeCheckCachableStats;
static EVH storeLateRelease;

/*
 * local variables
 */
static Stack<StoreEntry*> LateReleaseStack;
MemPool *StoreEntry::pool = NULL;

void *
StoreEntry::operator new (size_t bytecount)
{
    assert (bytecount == sizeof (StoreEntry));

    if (!pool) {
        pool = memPoolCreate ("StoreEntry", bytecount);
        memPoolSetChunkSize(pool, 2048 * 1024);
    }

    return memPoolAlloc (pool);
}

void
StoreEntry::operator delete (void *address)
{
    memPoolFree(pool, address);
}

size_t
StoreEntry::inUseCount()
{
    if (!pool)
        return 0;

    MemPoolStats stats;

    memPoolGetStats (&stats, pool);

    return stats.items_inuse;
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
                            aRead.callback.handler,
                            aRead.callback.data);
}

void
StoreEntry::delayAwareRead(int fd, char *buf, int len, IOCB *handler, void *data)
{
    size_t amountToRead = bytesWanted(Range<size_t>(0, len));
    /* sketch: readdeferer* = getdeferer.
     * ->deferRead (fd, buf, len, handler, data, DelayAwareRead, this)
     */

    if (amountToRead == 0) {
        assert (mem_obj);
        /* read ahead limit */
        /* Perhaps these two calls should both live in MemObject */
#if DELAY_POOLS

        if (!mem_obj->readAheadPolicyCanRead()) {
#endif
            mem_obj->delayRead(DeferredRead(DeferReader, this, CommRead(fd, buf, len, handler, data)));
            return;
#if DELAY_POOLS

        }

        /* delay id limit */
        mem_obj->mostBytesAllowed().delayRead(DeferredRead(DeferReader, this, CommRead(fd, buf, len, handler, data)));

        return;

#endif

    }

    comm_read(fd, buf, amountToRead, handler, data);
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
        debug(20, 1) ("storeClientType: adding to ENTRY_ABORTED entry\n");
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

StoreEntry *
new_StoreEntry(int mem_obj_flag, const char *url, const char *log_url)
{
    StoreEntry *e = NULL;
    e = new StoreEntry;

    if (mem_obj_flag)
        e->mem_obj = new MemObject(url, log_url);

    debug(20, 3) ("newStoreEntry: returning %p\n", e);

    e->expires = e->lastmod = e->lastref = e->timestamp = -1;

    e->swap_filen = -1;

    e->swap_dirn = -1;

    return e;
}

static void
destroy_MemObject(StoreEntry * e)
{
    storeSetMemStatus(e, NOT_IN_MEMORY);
    MemObject *mem = e->mem_obj;
    e->mem_obj = NULL;
    delete mem;
}

static void
destroyStoreEntry(void *data)
{
    StoreEntry *e = static_cast<StoreEntry *>(data);
    debug(20, 3) ("destroyStoreEntry: destroying %p\n", e);
    assert(e != NULL);

    if (e == NullStoreEntry::getInstance())
        return;

    destroy_MemObject(e);

    storeHashDelete(e);

    assert(e->key == NULL);

    delete e;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

void
storeHashInsert(StoreEntry * e, const cache_key * key)
{
    debug(20, 3) ("storeHashInsert: Inserting Entry %p key '%s'\n",
                  e, storeKeyText(key));
    e->key = storeKeyDup(key);
    hash_join(store_table, e);
}

static void
storeHashDelete(StoreEntry * e)
{
    hash_remove_link(store_table, e);
    storeKeyFree((const cache_key *)e->key);
    e->key = NULL;
}

/* -------------------------------------------------------------------------- */


/* get rid of memory copy of the object */
static void
storePurgeMem(StoreEntry * e)
{
    if (e->mem_obj == NULL)
        return;

    debug(20, 3) ("storePurgeMem: Freeing memory-copy of %s\n",
                  e->getMD5Text());

    destroy_MemObject(e);

    if (e->swap_status != SWAPOUT_DONE)
        storeRelease(e);
}

static void
storeEntryReferenced(StoreEntry * e)
{
    /* Notify the fs that we're referencing this object again */

    if (e->swap_dirn > -1)
        INDEXSD(e->swap_dirn)->reference(*e);

    /* Notify the memory cache that we're referencing this object again */
    if (e->mem_obj) {
        if (mem_policy->Referenced)
            mem_policy->Referenced(mem_policy, e, &e->mem_obj->repl);
    }
}

static void
storeEntryDereferenced(StoreEntry * e)
{
    /* Notify the fs that we're not referencing this object any more */

    if (e->swap_filen > -1)
        INDEXSD(e->swap_dirn)->dereference(*e);

    /* Notify the memory cache that we're not referencing this object any more */
    if (e->mem_obj) {
        if (mem_policy->Dereferenced)
            mem_policy->Dereferenced(mem_policy, e, &e->mem_obj->repl);
    }
}

void
storeLockObject(StoreEntry * e)
{
    e->lock_count++;
    debug(20, 3) ("storeLockObject: key '%s' count=%d\n",
                  e->getMD5Text(), (int) e->lock_count);
    e->lastref = squid_curtime;
    storeEntryReferenced(e);
}

void
StoreEntry::setReleaseFlag()
{
    if (EBIT_TEST(flags, RELEASE_REQUEST))
        return;

    debug(20, 3) ("StoreEntry::setReleaseFlag: '%s'\n", getMD5Text());

    EBIT_SET(flags, RELEASE_REQUEST);
}

void
storeReleaseRequest(StoreEntry * e)
{
    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
        return;

    e->setReleaseFlag();

    /*
     * Clear cachable flag here because we might get called before
     * anyone else even looks at the cachability flag.  Also, this
     * prevents httpMakePublic from really setting a public key.
     */
    EBIT_CLR(e->flags, ENTRY_CACHABLE);

    storeSetPrivateKey(e);
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */
int
storeUnlockObject(StoreEntry * e)
{
    e->lock_count--;
    debug(20, 3) ("storeUnlockObject: key '%s' count=%d\n",
                  e->getMD5Text(), e->lock_count);

    if (e->lock_count)
        return (int) e->lock_count;

    if (e->store_status == STORE_PENDING)
        e->setReleaseFlag();

    assert(storePendingNClients(e) == 0);

    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
        storeRelease(e);
    else if (storeKeepInMemory(e)) {
        storeEntryDereferenced(e);
        storeSetMemStatus(e, IN_MEMORY);
        e->mem_obj->unlinkRequest();
    } else {
        storeEntryDereferenced(e);

        if (EBIT_TEST(e->flags, KEY_PRIVATE))
            debug(20, 1) ("WARNING: %s:%d: found KEY_PRIVATE\n", __FILE__, __LINE__);

        /* storePurgeMem may free e */
        storePurgeMem(e);
    }

    return 0;
}

/* Lookup an object in the cache.
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *
storeGet(const cache_key * key)
{
    PROF_start(storeGet);
    debug(20, 3) ("storeGet: looking up %s\n", storeKeyText(key));
    StoreEntry *p = static_cast<StoreEntry *>(hash_lookup(store_table, key));
    PROF_stop(storeGet);
    return p;
}

void
StoreEntry::getPublicByRequestMethod  (StoreClient *aClient, HttpRequest * request, const method_t method)
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
StoreEntry::getPublic (StoreClient *aClient, const char *uri, const method_t method)
{
    assert (aClient);
    StoreEntry *result = storeGetPublic (uri, method);

    if (!result)
        result = NullStoreEntry::getInstance();

    aClient->created (result);
}

StoreEntry *
storeGetPublic(const char *uri, const method_t method)
{
    return storeGet(storeKeyPublic(uri, method));
}

StoreEntry *
storeGetPublicByRequestMethod(HttpRequest * req, const method_t method)
{
    return storeGet(storeKeyPublicByRequestMethod(req, method));
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

void
storeSetPrivateKey(StoreEntry * e)
{
    const cache_key *newkey;
    MemObject *mem = e->mem_obj;

    if (e->key && EBIT_TEST(e->flags, KEY_PRIVATE))
        return;			/* is already private */

    if (e->key) {
        if (e->swap_filen > -1)
            storeDirSwapLog(e, SWAP_LOG_DEL);

        storeHashDelete(e);
    }

    if (mem != NULL) {
        mem->id = getKeyCounter();
        newkey = storeKeyPrivate(mem->url, mem->method, mem->id);
    } else {
        newkey = storeKeyPrivate("JUNK", METHOD_NONE, getKeyCounter());
    }

    assert(hash_lookup(store_table, newkey) == NULL);
    EBIT_SET(e->flags, KEY_PRIVATE);
    storeHashInsert(e, newkey);
}

void
storeSetPublicKey(StoreEntry * e)
{
    StoreEntry *e2 = NULL;
    const cache_key *newkey;
    MemObject *mem = e->mem_obj;

    if (e->key && !EBIT_TEST(e->flags, KEY_PRIVATE))
        return;			/* is already public */

    assert(mem);

    /*
     * We can't make RELEASE_REQUEST objects public.  Depending on
     * when RELEASE_REQUEST gets set, we might not be swapping out
     * the object.  If we're not swapping out, then subsequent
     * store clients won't be able to access object data which has
     * been freed from memory.
     *
     * If RELEASE_REQUEST is set, then ENTRY_CACHABLE should not
     * be set, and storeSetPublicKey() should not be called.
     */
#if MORE_DEBUG_OUTPUT

    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
        debug(20, 1) ("assertion failed: RELEASE key %s, url %s\n",
                      e->key, mem->url);

#endif

    assert(!EBIT_TEST(e->flags, RELEASE_REQUEST));

    if (mem->request) {
        StoreEntry *pe;
        HttpRequest *request = mem->request;

        if (!mem->vary_headers) {
            /* First handle the case where the object no longer varies */
            safe_free(request->vary_headers);
        } else {
            if (request->vary_headers && strcmp(request->vary_headers, mem->vary_headers) != 0) {
                /* Oops.. the variance has changed. Kill the base object
                 * to record the new variance key
                 */
                safe_free(request->vary_headers);	/* free old "bad" variance key */
                pe = storeGetPublic(mem->url, mem->method);

                if (pe)
                    storeRelease(pe);
            }

            /* Make sure the request knows the variance status */
            if (!request->vary_headers) {
                const char *vary = httpMakeVaryMark(request, mem->getReply());

                if (vary)
                    request->vary_headers = xstrdup(vary);
            }
        }

        if (mem->vary_headers && !storeGetPublic(mem->url, mem->method)) {
            /* Create "vary" base object */
            String vary;
            pe = storeCreateEntry(mem->url, mem->log_url, request->flags, request->method);
            HttpVersion version(1, 0);
            /* We are allowed to do this typecast */
            httpReplySetHeaders((HttpReply *)pe->getReply(), version, HTTP_OK, "Internal marker object", "x-squid-internal/vary", -1, -1, squid_curtime + 100000);
            vary = httpHeaderGetList(&mem->getReply()->header, HDR_VARY);

            if (vary.size()) {
                /* Again, we own this structure layout */
                httpHeaderPutStr((HttpHeader *)&pe->getReply()->header, HDR_VARY, vary.buf());
                vary.clean();
            }

#if X_ACCELERATOR_VARY
            vary = httpHeaderGetList(&mem->getReply()->header, HDR_X_ACCELERATOR_VARY);

            if (vary.buf()) {
                /* Again, we own this structure layout */
                httpHeaderPutStr((HttpHeader *)&pe->getReply()->header, HDR_X_ACCELERATOR_VARY, vary.buf());
                vary.clean();
            }

#endif
            storeSetPublicKey(pe);

            storeBuffer(pe);

            /* TODO: remove this when the metadata is separated */
            {
                Packer p;
                packerToStoreInit(&p, pe);
                httpReplyPackHeadersInto(pe->getReply(), &p);
                packerClean(&p);
            }

            storeBufferFlush(pe);
            storeTimestampsSet(pe);
            pe->complete();
            storeUnlockObject(pe);
        }

        newkey = storeKeyPublicByRequest(mem->request);
    } else
        newkey = storeKeyPublic(mem->url, mem->method);

    if ((e2 = (StoreEntry *) hash_lookup(store_table, newkey))) {
        debug(20, 3) ("storeSetPublicKey: Making old '%s' private.\n", mem->url);
        storeSetPrivateKey(e2);
        storeRelease(e2);

        if (mem->request)
            newkey = storeKeyPublicByRequest(mem->request);
        else
            newkey = storeKeyPublic(mem->url, mem->method);
    }

    if (e->key)
        storeHashDelete(e);

    EBIT_CLR(e->flags, KEY_PRIVATE);

    storeHashInsert(e, newkey);

    if (e->swap_filen > -1)
        storeDirSwapLog(e, SWAP_LOG_ADD);
}

StoreEntry *
storeCreateEntry(const char *url, const char *log_url, request_flags flags, method_t method)
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    debug(20, 3) ("storeCreateEntry: '%s'\n", url);

    e = new_StoreEntry(STORE_ENTRY_WITH_MEMOBJ, url, log_url);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    mem->method = method;

    if (neighbors_do_private_keys || !flags.hierarchical)
        storeSetPrivateKey(e);
    else
        storeSetPublicKey(e);

    if (flags.cachable) {
        EBIT_SET(e->flags, ENTRY_CACHABLE);
        EBIT_CLR(e->flags, RELEASE_REQUEST);
    } else {
        /* storeReleaseRequest() clears ENTRY_CACHABLE */
        storeReleaseRequest(e);
    }

    e->store_status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_NONE;
    e->swap_filen = -1;
    e->swap_dirn = -1;
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = -1;		/* set in storeTimestampsSet() */
    e->ping_status = PING_NONE;
    EBIT_SET(e->flags, ENTRY_VALIDATED);
    return e;
}

/* Mark object as expired */
void
storeExpireNow(StoreEntry * e)
{
    debug(20, 3) ("storeExpireNow: '%s'\n", e->getMD5Text());
    e->expires = squid_curtime;
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

    InvokeHandlers(e);
    PROF_stop(storeWriteComplete);
}

void
StoreEntry::write (StoreIOBuffer writeBuffer)
{
    assert(mem_obj != NULL);
    assert(writeBuffer.length >= 0);
    /* This assert will change when we teach the store to update */
    assert(store_status == STORE_PENDING);

    if (!writeBuffer.length)
        return;

    PROF_start(StoreEntry_write);

    debug(20, 5) ("storeWrite: writing %u bytes for '%s'\n",
                  writeBuffer.length, getMD5Text());

    storeGetMemSpace(writeBuffer.length);

    mem_obj->write (writeBuffer, storeWriteComplete, this);

    PROF_stop(StoreEntry_write);
}

/* Append incoming data from a primary server to an entry. */
void
storeAppend(StoreEntry * e, const char *buf, int len)
{
    MemObject *mem = e->mem_obj;
    assert(mem != NULL);
    assert(len >= 0);
    assert(e->store_status == STORE_PENDING);

    StoreIOBuffer tempBuffer;
    tempBuffer.data = (char *)buf;
    tempBuffer.length = len;
    tempBuffer.offset = mem->endOffset() - (e->getReply() ? e->getReply()->hdr_sz : 0);
    e->write(tempBuffer);
}

void
#if STDC_HEADERS
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
#else
storeAppendPrintf(va_alist)
va_dcl
#endif
{
#if STDC_HEADERS
    va_list args;
    va_start(args, fmt);
#else

    va_list args;
    StoreEntry *e = NULL;
    const char *fmt = NULL;
    va_start(args);
    e = va_arg(args, StoreEntry *);
    fmt = va_arg(args, char *);
#endif

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
    storeAppend(e, buf, strlen(buf));
}

struct _store_check_cachable_hist
{

    struct
    {
        int non_get;
        int not_entry_cachable;
        int wrong_content_length;
        int negative_cached;
        int too_big;
        int too_small;
        int private_key;
        int too_many_open_files;
        int too_many_open_fds;
    }

    no;

    struct
    {
        int Default;
    }

    yes;
}

store_check_cachable_hist;

int
storeTooManyDiskFilesOpen(void)
{
    if (Config.max_open_disk_fds == 0)
        return 0;

    if (store_open_disk_fd > Config.max_open_disk_fds)
        return 1;

    return 0;
}

static int
storeCheckTooSmall(StoreEntry * e)
{
    MemObject * const mem = e->mem_obj;

    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
        return 0;

    if (STORE_OK == e->store_status)
        if (mem->object_sz < 0 ||
                static_cast<size_t>(mem->object_sz)
                < Config.Store.minObjectSize)
            return 1;
    if (e->getReply()
            ->content_length > -1)
        if (e->getReply()
                ->content_length < (int) Config.Store.minObjectSize)
            return 1;
    return 0;
}

int
storeCheckCachable(StoreEntry * e)
{
#if CACHE_ALL_METHODS

    if (e->mem_obj->method != METHOD_GET) {
        debug(20, 2) ("storeCheckCachable: NO: non-GET method\n");
        store_check_cachable_hist.no.non_get++;
    } else
#endif
        if (e->store_status == STORE_OK && EBIT_TEST(e->flags, ENTRY_BAD_LENGTH)) {
            debug(20, 2) ("storeCheckCachable: NO: wrong content-length\n");
            store_check_cachable_hist.no.wrong_content_length++;
        } else if (!EBIT_TEST(e->flags, ENTRY_CACHABLE)) {
            debug(20, 2) ("storeCheckCachable: NO: not cachable\n");
            store_check_cachable_hist.no.not_entry_cachable++;
        } else if (EBIT_TEST(e->flags, ENTRY_NEGCACHED)) {
            debug(20, 3) ("storeCheckCachable: NO: negative cached\n");
            store_check_cachable_hist.no.negative_cached++;
            return 0;		/* avoid release call below */
        } else if ((e->getReply()->content_length > 0 &&
                    static_cast<size_t>(e->getReply()->content_length)
                    > Config.Store.maxObjectSize) ||
                   static_cast<size_t>(e->mem_obj->endOffset()) > Config.Store.maxObjectSize) {
            debug(20, 2) ("storeCheckCachable: NO: too big\n");
            store_check_cachable_hist.no.too_big++;
        } else if (e->getReply()->content_length > (int) Config.Store.maxObjectSize) {
            debug(20, 2)
            ("storeCheckCachable: NO: too big\n");
            store_check_cachable_hist.no.too_big++;
        } else if (storeCheckTooSmall(e)) {
            debug(20, 2)
            ("storeCheckCachable: NO: too small\n");
            store_check_cachable_hist.no.too_small++;
        } else if (EBIT_TEST(e->flags, KEY_PRIVATE)) {
            debug(20, 3)
            ("storeCheckCachable: NO: private key\n");
            store_check_cachable_hist.no.private_key++;
        } else if (e->swap_status != SWAPOUT_NONE) {
            /*
             * here we checked the swap_status because the remaining
             * cases are only relevant only if we haven't started swapping
             * out the object yet.
             */
            return 1;
        } else if (storeTooManyDiskFilesOpen()) {
            debug(20, 2)
            ("storeCheckCachable: NO: too many disk files open\n");
            store_check_cachable_hist.no.too_many_open_files++;
        } else if (fdNFree() < RESERVED_FD) {
            debug(20, 2)
            ("storeCheckCachable: NO: too many FD's open\n");
            store_check_cachable_hist.no.too_many_open_fds++;
        } else {
            store_check_cachable_hist.yes.Default++;
            return 1;
        }

    storeReleaseRequest(e);
    /* storeReleaseRequest() cleared ENTRY_CACHABLE */
    return 0;
}

static void
storeCheckCachableStats(StoreEntry * sentry)
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
    debug(20, 3) ("storeComplete: '%s'\n", getMD5Text());

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
        storeReleaseRequest(this);
    }

#if USE_CACHE_DIGESTS
    if (mem_obj->request)
        mem_obj->request->hier.store_complete_stop = current_time;

#endif
    /*
     * We used to call InvokeHandlers, then storeSwapOut.  However,
     * Madhukar Reddy <myreddy@persistence.com> reported that
     * responses without content length would sometimes get released
     * in client_side, thinking that the response is incomplete.
     */
    InvokeHandlers(this);
}

/*
 * Someone wants to abort this transfer.  Set the reason in the
 * request structure, call the server-side callback and mark the
 * entry for releasing
 */
void
storeAbort(StoreEntry * e)
{
    statCounter.aborted_requests++;
    MemObject *mem = e->mem_obj;
    assert(e->store_status == STORE_PENDING);
    assert(mem != NULL);
    debug(20, 6) ("storeAbort: %s\n", e->getMD5Text());
    storeLockObject(e);		/* lock while aborting */
    storeNegativeCache(e);
    storeReleaseRequest(e);
    EBIT_SET(e->flags, ENTRY_ABORTED);
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->store_status = STORE_OK;
    /*
     * We assign an object length here.  The only other place we assign
     * the object length is in storeComplete()
     */
    /* RBC: What do we need an object length for? we've just aborted the
     * request, the request is private and negatively cached. Surely
     * the object length is inappropriate to set.
     */
    mem->object_sz = mem->endOffset();
    /* Notify the server side */

    if (mem->abort.callback) {
        eventAdd("mem->abort.callback",
                 mem->abort.callback,
                 mem->abort.data,
                 0.0,
                 0);
        mem->abort.callback = NULL;
        mem->abort.data = NULL;
    }

    /* XXX Should we reverse these two, so that there is no
     * unneeded disk swapping triggered? 
     */
    /* Notify the client side */
    InvokeHandlers(e);

    /* Close any swapout file */
    storeSwapOutFileClose(e);

    storeUnlockObject(e);	/* unlock */
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

    debug(20, 2) ("storeGetMemSpace: Starting, need %d pages\n", pages_needed);

    /* XXX what to set as max_scan here? */
    walker = mem_policy->PurgeInit(mem_policy, 100000);

    while ((e = walker->Next(walker))) {
        storePurgeMem(e);
        released++;

        if (mem_node::InUseCount() + pages_needed < store_pages_max)
            break;
    }

    walker->Done(walker);
    debug(20, 3) ("storeGetMemSpace stats:\n");
    debug(20, 3) ("  %6d HOT objects\n", hot_obj_count);
    debug(20, 3) ("  %6d were released\n", released);
    PROF_stop(storeGetMemSpace);
}

/* The maximum objects to scan for maintain storage space */
#define MAINTAIN_MAX_SCAN	1024
#define MAINTAIN_MAX_REMOVE	64

/*
 * This routine is to be called by main loop in main.c.
 * It removes expired objects on only one bucket for each time called.
 *
 * This should get called 1/s from main().
 */
void
storeMaintainSwapSpace(void *datanotused)
{
    int i;
    SwapDir *SD;
    static time_t last_warn_time = 0;

    PROF_start(storeMaintainSwapSpace);
    /* walk each fs */

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
        /* call the maintain function .. */
        SD = INDEXSD(i);
        /* XXX FixMe: This should be done "in parallell" on the different
         * cache_dirs, not one at a time.
         */
        SD->maintainfs();
    }

    if (store_swap_size > Config.Swap.maxSize) {
        if (squid_curtime - last_warn_time > 10) {
            debug(20, 0) ("WARNING: Disk space over limit: %lu KB > %lu KB\n",
                          (long unsigned) store_swap_size, (long unsigned) Config.Swap.maxSize);
            last_warn_time = squid_curtime;
        }
    }

    /* Reregister a maintain event .. */
    eventAdd("MaintainSwapSpace", storeMaintainSwapSpace, NULL, 1.0, 1);

    PROF_stop(storeMaintainSwapSpace);
}


/* release an object from a cache */
void
storeRelease(StoreEntry * e)
{
    PROF_start(storeRelease);
    debug(20, 3) ("storeRelease: Releasing: '%s'\n", e->getMD5Text());
    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */

    if (storeEntryLocked(e)) {
        storeExpireNow(e);
        debug(20, 3) ("storeRelease: Only setting RELEASE_REQUEST bit\n");
        storeReleaseRequest(e);
        PROF_stop(storeRelease);
        return;
    }

    if (store_dirs_rebuilding && e->swap_filen > -1) {
        storeSetPrivateKey(e);

        if (e->mem_obj)
            destroy_MemObject(e);

        if (e->swap_filen > -1) {
            /*
             * Fake a call to storeLockObject().  When rebuilding is done,
             * we'll just call storeUnlockObject() on these.
             */
            e->lock_count++;
            e->setReleaseFlag();
            LateReleaseStack.push_back(e);
            PROF_stop(storeRelease);
            return;
        } else {
            destroyStoreEntry(e);
        }
    }

    storeLog(STORE_LOG_RELEASE, e);

    if (e->swap_filen > -1) {
        storeUnlink(e);

        if (e->swap_status == SWAPOUT_DONE)
            if (EBIT_TEST(e->flags, ENTRY_VALIDATED))
                storeDirUpdateSwapSize(INDEXSD(e->swap_dirn), e->swap_file_sz, -1);

        if (!EBIT_TEST(e->flags, KEY_PRIVATE))
            storeDirSwapLog(e, SWAP_LOG_DEL);

#if 0
        /* From 2.4. I think we do this in storeUnlink? */
        storeSwapFileNumberSet(e, -1);

#endif

    }

    storeSetMemStatus(e, NOT_IN_MEMORY);
    destroyStoreEntry(e);
    PROF_stop(storeRelease);
}

static void
storeLateRelease(void *unused)
{
    StoreEntry *e;
    int i;
    static int n = 0;

    if (store_dirs_rebuilding) {
        eventAdd("storeLateRelease", storeLateRelease, NULL, 1.0, 1);
        return;
    }

    for (i = 0; i < 10; i++) {
        e = LateReleaseStack.pop();

        if (e == NULL) {
            /* done! */
            debug(20, 1) ("storeLateRelease: released %d objects\n", n);
            return;
        }

        storeUnlockObject(e);
        n++;
    }

    eventAdd("storeLateRelease", storeLateRelease, NULL, 0.0, 1);
}

/* return 1 if a store entry is locked */
int
storeEntryLocked(const StoreEntry * e)
{
    if (e->lock_count)
        return 1;

    if (e->swap_status == SWAPOUT_WRITING)
        return 1;

    if (e->store_status == STORE_PENDING)
        return 1;

    /*
     * SPECIAL, PUBLIC entries should be "locked"
     */
    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
        if (!EBIT_TEST(e->flags, KEY_PRIVATE))
            return 1;

    return 0;
}

bool
StoreEntry::validLength() const
{
    int diff;
    const HttpReply *reply;
    assert(mem_obj != NULL);
    reply = getReply();
    debug(20, 3) ("storeEntryValidLength: Checking '%s'\n", getMD5Text());
    debug(20, 5) ("storeEntryValidLength:     object_len = %d\n",
                  objectLen(this));
    debug(20, 5) ("storeEntryValidLength:         hdr_sz = %d\n",
                  reply->hdr_sz);
    debug(20, 5) ("storeEntryValidLength: content_length = %d\n",
                  reply->content_length);

    if (reply->content_length < 0) {
        debug(20, 5) ("storeEntryValidLength: Unspecified content length: %s\n",
                      getMD5Text());
        return 1;
    }

    if (reply->hdr_sz == 0) {
        debug(20, 5) ("storeEntryValidLength: Zero header size: %s\n",
                      getMD5Text());
        return 1;
    }

    if (mem_obj->method == METHOD_HEAD) {
        debug(20, 5) ("storeEntryValidLength: HEAD request: %s\n",
                      getMD5Text());
        return 1;
    }

    if (reply->sline.status == HTTP_NOT_MODIFIED)
        return 1;

    if (reply->sline.status == HTTP_NO_CONTENT)
        return 1;

    diff = reply->hdr_sz + reply->content_length - objectLen(this);

    if (diff == 0)
        return 1;

    debug(20, 3) ("storeEntryValidLength: %d bytes too %s; '%s'\n",
                  diff < 0 ? -diff : diff,
                  diff < 0 ? "big" : "small",
                  getMD5Text());

    return 0;
}

static void
storeInitHashValues(void)
{
    long int i;
    /* Calculate size of hash table (maximum currently 64k buckets).  */
    i = Config.Swap.maxSize / Config.Store.avgObjectSize;
    debug(20, 1) ("Swap maxSize %ld KB, estimated %ld objects\n",
                  (long int) Config.Swap.maxSize, i);
    i /= Config.Store.objectsPerBucket;
    debug(20, 1) ("Target number of buckets: %ld\n", i);
    /* ideally the full scan period should be configurable, for the
     * moment it remains at approximately 24 hours.  */
    store_hash_buckets = storeKeyHashBuckets(i);
    debug(20, 1) ("Using %d Store buckets\n", store_hash_buckets);
    debug(20, 1) ("Max Mem  size: %ld KB\n", (long int) Config.memMaxSize >> 10);
    debug(20, 1) ("Max Swap size: %ld KB\n", (long int) Config.Swap.maxSize);
}

void
storeInit(void)
{
    storeKeyInit();
    storeInitHashValues();
    store_table = hash_create(storeKeyHashCmp,
                              store_hash_buckets, storeKeyHashHash);
    mem_policy = createRemovalPolicy(Config.memPolicy);
    storeDigestInit();
    storeLogOpen();
    eventAdd("storeLateRelease", storeLateRelease, NULL, 1.0, 1);
    storeDirInit();
    storeRebuildStart();
    cachemgrRegister("storedir",
                     "Store Directory Stats",
                     storeDirStats, 0, 1);
    cachemgrRegister("store_check_cachable_stats",
                     "storeCheckCachable() Stats",
                     storeCheckCachableStats, 0, 1);
    cachemgrRegister("store_io",
                     "Store IO Interface Stats",
                     storeIOStats, 0, 1);
}

void
storeConfigure(void)
{
    store_swap_high = (long) (((float) Config.Swap.maxSize *
                               (float) Config.Swap.highWaterMark) / (float) 100);
    store_swap_low = (long) (((float) Config.Swap.maxSize *
                              (float) Config.Swap.lowWaterMark) / (float) 100);
    store_pages_max = Config.memMaxSize / SM_PAGE_SIZE;
}

static int
storeKeepInMemory(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;

    if (mem == NULL)
        return 0;

    if (mem->data_hdr.size() == 0)
        return 0;

    return mem->inmem_lo == 0;
}

int
storeCheckNegativeHit(StoreEntry * e)
{
    if (!EBIT_TEST(e->flags, ENTRY_NEGCACHED))
        return 0;

    if (e->expires <= squid_curtime)
        return 0;

    if (e->store_status != STORE_OK)
        return 0;

    return 1;
}

void
storeNegativeCache(StoreEntry * e)
{
    e->expires = squid_curtime + Config.negativeTtl;
    EBIT_SET(e->flags, ENTRY_NEGCACHED);
}

void
storeFreeMemory(void)
{
    hashFreeItems(store_table, destroyStoreEntry);
    hashFreeMemory(store_table);
    store_table = NULL;
#if USE_CACHE_DIGESTS

    if (store_digest)
        cacheDigestDestroy(store_digest);

#endif

    store_digest = NULL;
}

int
expiresMoreThan(time_t expires, time_t when)
{
    if (expires < 0)		/* No Expires given */
        return 1;

    return (expires > (squid_curtime + when));
}

int
storeEntryValidToSend(StoreEntry * e)
{
    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
        return 0;

    if (EBIT_TEST(e->flags, ENTRY_NEGCACHED))
        if (e->expires <= squid_curtime)
            return 0;

    if (EBIT_TEST(e->flags, ENTRY_ABORTED))
        return 0;

    return 1;
}

void
storeTimestampsSet(StoreEntry * entry)
{
    const HttpReply *reply = entry->getReply();
    time_t served_date = reply->date;
    int age = httpHeaderGetInt(&reply->header, HDR_AGE);
    /*
     * The timestamp calculations below tries to mimic the properties
     * of the age calculation in RFC2616 section 13.2.3. The implementaion
     * isn't complete, and the most notable exception from the RFC is that
     * this does not account for response_delay, but it probably does
     * not matter much as this is calculated immediately when the headers
     * are received, not when the whole response has been received.
     */
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

    entry->expires = reply->expires;

    entry->lastmod = reply->last_modified;

    entry->timestamp = served_date;
}

void
storeRegisterAbort(StoreEntry * e, STABH * cb, void *data)
{
    MemObject *mem = e->mem_obj;
    assert(mem);
    assert(mem->abort.callback == NULL);
    mem->abort.callback = cb;
    mem->abort.data = data;
}

void
storeUnregisterAbort(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    assert(mem);
    mem->abort.callback = NULL;
}

void
storeEntryDump(const StoreEntry * e, int l)
{
    debug(20, l) ("StoreEntry->key: %s\n", e->getMD5Text());
    debug(20, l) ("StoreEntry->next: %p\n", e->next);
    debug(20, l) ("StoreEntry->mem_obj: %p\n", e->mem_obj);
    debug(20, l) ("StoreEntry->timestamp: %d\n", (int) e->timestamp);
    debug(20, l) ("StoreEntry->lastref: %d\n", (int) e->lastref);
    debug(20, l) ("StoreEntry->expires: %d\n", (int) e->expires);
    debug(20, l) ("StoreEntry->lastmod: %d\n", (int) e->lastmod);
    debug(20, l) ("StoreEntry->swap_file_sz: %d\n", (int) e->swap_file_sz);
    debug(20, l) ("StoreEntry->refcount: %d\n", e->refcount);
    debug(20, l) ("StoreEntry->flags: %s\n", storeEntryFlags(e));
    debug(20, l) ("StoreEntry->swap_dirn: %d\n", (int) e->swap_dirn);
    debug(20, l) ("StoreEntry->swap_filen: %d\n", (int) e->swap_filen);
    debug(20, l) ("StoreEntry->lock_count: %d\n", (int) e->lock_count);
    debug(20, l) ("StoreEntry->mem_status: %d\n", (int) e->mem_status);
    debug(20, l) ("StoreEntry->ping_status: %d\n", (int) e->ping_status);
    debug(20, l) ("StoreEntry->store_status: %d\n", (int) e->store_status);
    debug(20, l) ("StoreEntry->swap_status: %d\n", (int) e->swap_status);
}

/*
 * NOTE, this function assumes only two mem states
 */
void
storeSetMemStatus(StoreEntry * e, mem_status_t new_status)
{
    MemObject *mem = e->mem_obj;

    if (new_status == e->mem_status)
        return;

    assert(mem != NULL);

    if (new_status == IN_MEMORY) {
        assert(mem->inmem_lo == 0);

        if (EBIT_TEST(e->flags, ENTRY_SPECIAL)) {
            debug(20, 4) ("storeSetMemStatus: not inserting special %s into policy\n",
                          mem->url);
        } else {
            mem_policy->Add(mem_policy, e, &mem->repl);
            debug(20, 4) ("storeSetMemStatus: inserted mem node %s\n",
                          mem->url);
        }

        hot_obj_count++;
    } else {
        if (EBIT_TEST(e->flags, ENTRY_SPECIAL)) {
            debug(20, 4) ("storeSetMemStatus: special entry %s\n",
                          mem->url);
        } else {
            mem_policy->Remove(mem_policy, e, &mem->repl);
            debug(20, 4) ("storeSetMemStatus: removed mem node %s\n",
                          mem->url);
        }

        hot_obj_count--;
    }

    e->mem_status = new_status;
}

const char *
storeUrl(const StoreEntry * e)
{
    if (e == NULL)
        return "[null_entry]";
    else if (e->mem_obj == NULL)
        return "[null_mem_obj]";
    else
        return e->mem_obj->url;
}

void
storeCreateMemObject(StoreEntry * e, const char *url, const char *log_url)
{
    if (e->mem_obj)
        return;

    e->mem_obj = new MemObject(url, log_url);
}

/* this just sets DELAY_SENDING */
void
storeBuffer(StoreEntry * e)
{
    EBIT_SET(e->flags, DELAY_SENDING);
}

/* this just clears DELAY_SENDING and Invokes the handlers */
void
storeBufferFlush(StoreEntry * e)
{
    EBIT_CLR(e->flags, DELAY_SENDING);
    InvokeHandlers(e);
}

ssize_t
objectLen(const StoreEntry * e)
{
    assert(e->mem_obj != NULL);
    return e->mem_obj->object_sz;
}

int
contentLen(const StoreEntry * e)
{
    assert(e->mem_obj != NULL);
    assert(e->getReply() != NULL);
    return objectLen(e) - e->getReply()->hdr_sz;

}

HttpReply const *
StoreEntry::getReply () const
{
    if (NULL == mem_obj)
        return NULL;

    return mem_obj->getReply();
}

void
storeEntryReset(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    assert (mem);
    debug(20, 3) ("storeEntryReset: %s\n", storeUrl(e));
    mem->reset();
    httpReplyReset((HttpReply *)e->getReply());
    e->expires = e->lastmod = e->timestamp = -1;
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

    debug(20, 1) ("ERROR: Unknown policy %s\n", settings->type);
    debug(20, 1) ("ERROR: Be sure to have set cache_replacement_policy\n");
    debug(20, 1) ("ERROR:   and memory_replacement_policy in squid.conf!\n");
    fatalf("ERROR: Unknown policy %s\n", settings->type);
    return NULL;		/* NOTREACHED */
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

/* Replace a store entry with
 * a new reply. This eats the reply.
 */
void
storeEntryReplaceObject(StoreEntry * e, HttpReply * rep)
{
    MemObject * const mem = e->mem_obj;
    HttpReply *myrep;
    Packer p;
    debug(20, 3) ("storeEntryReplaceObject: %s\n", storeUrl(e));

    if (!mem) {
        debug (20,0)("Attempt to replace object with no in-memory representation\n");
        return;
    }

    /* TODO: check that there is at most 1 store client ? */
    myrep = (HttpReply *)e->getReply(); /* we are allowed to do this */

    /* move info to the mem_obj->reply */
    httpReplyAbsorb(myrep, rep);

    /* TODO: when we store headers serparately remove the header portion */
    /* TODO: mark the length of the headers ? */
    /* We ONLY want the headers */
    packerToStoreInit(&p, e);

    assert (e->isEmpty());

    httpReplyPackHeadersInto(e->getReply(), &p);

    myrep->hdr_sz = e->mem_obj->endOffset();

    httpBodyPackInto(&e->getReply()->body, &p);

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
    debug(20, 7) ("storeSwapOut: %s\n", storeUrl(this));
    debug(20, 7) ("storeSwapOut: store_status = %s\n",
                  storeStatusStr[store_status]);

    if (EBIT_TEST(flags, ENTRY_ABORTED)) {
        assert(EBIT_TEST(flags, RELEASE_REQUEST));
        storeSwapOutFileClose(this);
        return false;
    }

    if (EBIT_TEST(flags, ENTRY_SPECIAL)) {
        debug(20, 3) ("storeSwapOut: %s SPECIAL\n", storeUrl(this));
        return false;
    }

    return true;
}

void
StoreEntry::trimMemory()
{
    if (mem_obj->policyLowestOffsetToKeep() == 0)
        /* Nothing to do */
        return;

    assert (mem_obj->policyLowestOffsetToKeep() > 0);

    if (!storeSwapOutAble(this)) {
        /*
         * Its not swap-able, and we're about to delete a chunk,
         * so we must make it PRIVATE.  This is tricky/ugly because
         * for the most part, we treat swapable == cachable here.
         */
        storeReleaseRequest(this);
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

    debug(88, 3) ("modifiedSince: '%s'\n", storeUrl(this));

    debug(88, 3) ("modifiedSince: mod_time = %ld\n", (long int) mod_time);

    if (mod_time < 0)
        return true;

    /* Find size of the object */
    object_length = getReply()->content_length;

    if (object_length < 0)
        object_length = contentLen(this);

    if (mod_time > request->ims) {
        debug(88, 3) ("--> YES: entry newer than client\n");
        return true;
    } else if (mod_time < request->ims) {
        debug(88, 3) ("-->  NO: entry older than client\n");
        return false;
    } else if (request->imslen < 0) {
        debug(88, 3) ("-->  NO: same LMT, no client length\n");
        return false;
    } else if (request->imslen == object_length) {
        debug(88, 3) ("-->  NO: same LMT, same length\n");
        return false;
    } else {
        debug(88, 3) ("--> YES: same LMT, different length\n");
        return true;
    }
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
