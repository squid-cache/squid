
/*
 * $Id: store.cc,v 1.468 1998/10/09 17:53:01 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
    "PING_TIMEOUT",
    "PING_DONE"
};

const char *storeStatusStr[] =
{
    "STORE_OK",
    "STORE_PENDING",
    "STORE_ABORTED"
};

const char *swapStatusStr[] =
{
    "SWAPOUT_NONE",
    "SWAPOUT_OPENING",
    "SWAPOUT_WRITING",
    "SWAPOUT_DONE"
};

typedef struct lock_ctrl_t {
    SIH *callback;
    void *callback_data;
    StoreEntry *e;
} lock_ctrl_t;

/*
 * local function prototypes
 */
static int storeCheckExpired(const StoreEntry *);
static int storeEntryLocked(const StoreEntry *);
static int storeEntryValidLength(const StoreEntry *);
static void storeGetMemSpace(int);
static void storeHashDelete(StoreEntry *);
static MemObject *new_MemObject(const char *, const char *);
static void destroy_MemObject(StoreEntry *);
static FREE destroy_StoreEntry;
static void storePurgeMem(StoreEntry *);
static int getKeyCounter(void);
static int storeKeepInMemory(const StoreEntry *);
static OBJH storeCheckCachableStats;

/*
 * local variables
 */
static dlink_list inmem_list;
static int store_pages_high = 0;
static int store_pages_low = 0;
static int store_swap_high = 0;
static int store_swap_low = 0;
static int store_swap_mid = 0;
static int store_maintain_rate;

static MemObject *
new_MemObject(const char *url, const char *log_url)
{
    MemObject *mem = memAllocate(MEM_MEMOBJECT);
    mem->reply = httpReplyCreate();
    mem->url = xstrdup(url);
    mem->log_url = xstrdup(log_url);
    mem->swapout.fd = -1;
    mem->object_sz = -1;
    mem->fd = -1;
    /* XXX account log_url */
    debug(20, 3) ("new_MemObject: returning %p\n", mem);
    return mem;
}

StoreEntry *
new_StoreEntry(int mem_obj_flag, const char *url, const char *log_url)
{
    StoreEntry *e = NULL;
    e = memAllocate(MEM_STOREENTRY);
    if (mem_obj_flag)
	e->mem_obj = new_MemObject(url, log_url);
    debug(20, 3) ("new_StoreEntry: returning %p\n", e);
    e->expires = e->lastmod = e->lastref = e->timestamp = -1;
    return e;
}

static void
destroy_MemObject(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    const Ctx ctx = ctx_enter(mem->url);
    debug(20, 3) ("destroy_MemObject: destroying %p\n", mem);
    e->mem_obj = NULL;
    if (!shutting_down)
	assert(mem->swapout.fd == -1);
    stmemFree(&mem->data_hdr);
    mem->inmem_hi = 0;
    /* XXX account log_url */
#if USE_ASYNC_IO
    while (mem->clients != NULL)
	storeUnregister(e, mem->clients->callback_data);
#endif
    /*
     * There is no way to abort FD-less clients, so they might
     * still have mem->clients set if mem->fd == -1
     */
    assert(mem->fd == -1 || mem->clients == NULL);
    httpReplyDestroy(mem->reply);
    requestUnlink(mem->request);
    mem->request = NULL;
    ctx_exit(ctx);		/* must exit before we free mem->url */
    safe_free(mem->url);
    safe_free(mem->log_url);
    memFree(MEM_MEMOBJECT, mem);
}

static void
destroy_StoreEntry(void *data)
{
    StoreEntry *e = data;
    debug(20, 3) ("destroy_StoreEntry: destroying %p\n", e);
    assert(e != NULL);
    if (e->mem_obj)
	destroy_MemObject(e);
    storeHashDelete(e);
    assert(e->key == NULL);
    memFree(MEM_STOREENTRY, e);
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

void
storeHashInsert(StoreEntry * e, const cache_key * key)
{
    debug(20, 3) ("storeHashInsert: Inserting Entry %p key '%s'\n",
	e, storeKeyText(key));
    e->key = storeKeyDup(key);
    hash_join(store_table, (hash_link *) e);
    dlinkAdd(e, &e->lru, &store_list);
}

static void
storeHashDelete(StoreEntry * e)
{
    hash_remove_link(store_table, (hash_link *) e);
    dlinkDelete(&e->lru, &store_list);
    storeKeyFree(e->key);
    e->key = NULL;
}

/* -------------------------------------------------------------------------- */


/* get rid of memory copy of the object */
/* Only call this if storeCheckPurgeMem(e) returns 1 */
static void
storePurgeMem(StoreEntry * e)
{
    if (e->mem_obj == NULL)
	return;
    debug(20, 3) ("storePurgeMem: Freeing memory-copy of %s\n",
	storeKeyText(e->key));
    storeSetMemStatus(e, NOT_IN_MEMORY);
    destroy_MemObject(e);
    if (e->swap_status != SWAPOUT_DONE)
	storeRelease(e);
}

void
storeLockObject(StoreEntry * e)
{
    if (e->lock_count++ == 0) {
	dlinkDelete(&e->lru, &store_list);
	dlinkAdd(e, &e->lru, &store_list);
    }
    debug(20, 3) ("storeLockObject: key '%s' count=%d\n",
	storeKeyText(e->key), (int) e->lock_count);
    e->lastref = squid_curtime;
}

void
storeReleaseRequest(StoreEntry * e)
{
    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
	return;
    debug(20, 3) ("storeReleaseRequest: '%s'\n", storeKeyText(e->key));
    EBIT_SET(e->flags, RELEASE_REQUEST);
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
	storeKeyText(e->key), e->lock_count);
    if (e->lock_count)
	return (int) e->lock_count;
    if (e->store_status == STORE_PENDING) {
	assert(!EBIT_TEST(e->flags, ENTRY_DISPATCHED));
	EBIT_SET(e->flags, RELEASE_REQUEST);
    }
    assert(storePendingNClients(e) == 0);
    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
	storeRelease(e);
    else if (storeKeepInMemory(e)) {
	storeSetMemStatus(e, IN_MEMORY);
	requestUnlink(e->mem_obj->request);
	e->mem_obj->request = NULL;
    } else {
	storePurgeMem(e);
	if (EBIT_TEST(e->flags, KEY_PRIVATE)) {
	    dlinkDelete(&e->lru, &store_list);
	    dlinkAddTail(e, &e->lru, &store_list);
	}
    }
    return 0;
}

/* Lookup an object in the cache. 
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *
storeGet(const cache_key * key)
{
    debug(20, 3) ("storeGet: looking up %s\n", storeKeyText(key));
    return (StoreEntry *) hash_lookup(store_table, key);
}

StoreEntry *
storeGetPublic(const char *uri, const method_t method)
{
    const cache_key *key;
    StoreEntry *e;
    key = storeKeyPublic(uri, method);
    e = storeGet(key);
    if (e == NULL && squid_curtime < 909000000) {
	key = storeKeyPublicOld(uri, method);
	e = storeGet(key);
    }
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
	if (e->swap_file_number > -1)
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
    assert(!EBIT_TEST(e->flags, RELEASE_REQUEST));
    newkey = storeKeyPublic(mem->url, mem->method);
    if ((e2 = (StoreEntry *) hash_lookup(store_table, newkey))) {
	debug(20, 3) ("storeSetPublicKey: Making old '%s' private.\n", mem->url);
	storeSetPrivateKey(e2);
	storeRelease(e2);
	newkey = storeKeyPublic(mem->url, mem->method);
    }
    if (e->key)
	storeHashDelete(e);
    EBIT_CLR(e->flags, KEY_PRIVATE);
    storeHashInsert(e, newkey);
    if (e->swap_file_number > -1)
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
	EBIT_CLR(e->flags, ENTRY_CACHABLE);
	storeReleaseRequest(e);
    }
    e->store_status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_NONE;
    e->swap_file_number = -1;
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = 0;		/* set in storeTimestampsSet() */
    e->ping_status = PING_NONE;
    EBIT_SET(e->flags, ENTRY_VALIDATED);
#ifdef PPNR_WIP
    EBIT_SET(e->flags, ENTRY_FWD_HDR_WAIT);
#endif /* PPNR_WIP */
    return e;
}

/* Mark object as expired */
void
storeExpireNow(StoreEntry * e)
{
    debug(20, 3) ("storeExpireNow: '%s'\n", storeKeyText(e->key));
    e->expires = squid_curtime;
}

/* Append incoming data from a primary server to an entry. */
void
storeAppend(StoreEntry * e, const char *buf, int len)
{
    MemObject *mem = e->mem_obj;
    assert(mem != NULL);
    assert(len >= 0);
    if (len) {
	debug(20, 5) ("storeAppend: appending %d bytes for '%s'\n",
	    len,
	    storeKeyText(e->key));
	storeGetMemSpace(len);
	stmemAppend(&mem->data_hdr, buf, len);
	mem->inmem_hi += len;
    }
    if (EBIT_TEST(e->flags, DELAY_SENDING))
	return;
#ifdef OPTIMISTIC_IO
    storeLockObject(e);
#endif
    InvokeHandlers(e);
    storeCheckSwapOut(e);
#ifdef OPTIMISTIC_IO
    storeUnlockObject(e);
#endif
}

#ifdef __STDC__
void
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
#else
void
storeAppendPrintf(va_alist)
     va_dcl
{
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

struct _store_check_cachable_hist {
    struct {
	int non_get;
	int not_entry_cachable;
	int release_request;
	int wrong_content_length;
	int negative_cached;
	int too_big;
	int private_key;
	int too_many_open_files;
	int lru_age_too_low;
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
    if (open_disk_fd > Config.max_open_disk_fds)
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
    if (!EBIT_TEST(e->flags, ENTRY_CACHABLE)) {
	debug(20, 2) ("storeCheckCachable: NO: not cachable\n");
	store_check_cachable_hist.no.not_entry_cachable++;
    } else if (EBIT_TEST(e->flags, RELEASE_REQUEST)) {
	debug(20, 2) ("storeCheckCachable: NO: release requested\n");
	store_check_cachable_hist.no.release_request++;
    } else if (e->store_status == STORE_OK && EBIT_TEST(e->flags, ENTRY_BAD_LENGTH)) {
	debug(20, 2) ("storeCheckCachable: NO: wrong content-length\n");
	store_check_cachable_hist.no.wrong_content_length++;
    } else if (EBIT_TEST(e->flags, ENTRY_NEGCACHED)) {
	debug(20, 3) ("storeCheckCachable: NO: negative cached\n");
	store_check_cachable_hist.no.negative_cached++;
	return 0;		/* avoid release call below */
    } else if (e->mem_obj->inmem_hi > Config.Store.maxObjectSize) {
	debug(20, 2) ("storeCheckCachable: NO: too big\n");
	store_check_cachable_hist.no.too_big++;
    } else if (EBIT_TEST(e->flags, KEY_PRIVATE)) {
	debug(20, 3) ("storeCheckCachable: NO: private key\n");
	store_check_cachable_hist.no.private_key++;
    } else if (storeTooManyDiskFilesOpen()) {
	debug(20, 2) ("storeCheckCachable: NO: too many disk files open\n");
	store_check_cachable_hist.no.too_many_open_files++;
    } else if (storeExpiredReferenceAge() < 300) {
	debug(20, 2) ("storeCheckCachable: NO: LRU Age = %d\n",
	    storeExpiredReferenceAge());
	store_check_cachable_hist.no.lru_age_too_low++;
    } else {
	store_check_cachable_hist.yes.Default++;
	return 1;
    }
    storeReleaseRequest(e);
    EBIT_CLR(e->flags, ENTRY_CACHABLE);
    return 0;
}

static void
storeCheckCachableStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "no.non_get\t%d\n",
	store_check_cachable_hist.no.non_get);
    storeAppendPrintf(sentry, "no.not_entry_cachable\t%d\n",
	store_check_cachable_hist.no.not_entry_cachable);
    storeAppendPrintf(sentry, "no.release_request\t%d\n",
	store_check_cachable_hist.no.release_request);
    storeAppendPrintf(sentry, "no.wrong_content_length\t%d\n",
	store_check_cachable_hist.no.wrong_content_length);
    storeAppendPrintf(sentry, "no.negative_cached\t%d\n",
	store_check_cachable_hist.no.negative_cached);
    storeAppendPrintf(sentry, "no.too_big\t%d\n",
	store_check_cachable_hist.no.too_big);
    storeAppendPrintf(sentry, "no.private_key\t%d\n",
	store_check_cachable_hist.no.private_key);
    storeAppendPrintf(sentry, "no.too_many_open_files\t%d\n",
	store_check_cachable_hist.no.too_many_open_files);
    storeAppendPrintf(sentry, "no.lru_age_too_low\t%d\n",
	store_check_cachable_hist.no.lru_age_too_low);
    storeAppendPrintf(sentry, "yes.default\t%d\n",
	store_check_cachable_hist.yes.Default);
}

/* Complete transfer into the local cache.  */
void
storeComplete(StoreEntry * e)
{
    debug(20, 3) ("storeComplete: '%s'\n", storeKeyText(e->key));
    assert(e->store_status == STORE_PENDING);
    e->mem_obj->object_sz = e->mem_obj->inmem_hi;
    e->store_status = STORE_OK;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!storeEntryValidLength(e)) {
	EBIT_SET(e->flags, ENTRY_BAD_LENGTH);
	storeReleaseRequest(e);
    }
#if USE_CACHE_DIGESTS
    if (e->mem_obj->request)
	e->mem_obj->request->hier.store_complete_stop = current_time;
#endif
    InvokeHandlers(e);
    storeCheckSwapOut(e);
}

#ifdef PPNR_WIP
void
storePPNR(StoreEntry * e)
{
    assert(EBIT_TEST(e->flags, ENTRY_FWD_HDR_WAIT));
    EBIT_CLR(e->flags, ENTRY_FWD_HDR_WAIT);
}

#endif /* PPNR_WIP */

/*
 * Someone wants to abort this transfer.  Set the reason in the
 * request structure, call the server-side callback and mark the
 * entry for releasing 
 */
void
storeAbort(StoreEntry * e, int cbflag)
{
    MemObject *mem = e->mem_obj;
    STABH *callback;
    void *data;
    assert(e->store_status == STORE_PENDING);
    assert(mem != NULL);
    debug(20, 6) ("storeAbort: %s\n", storeKeyText(e->key));
    storeLockObject(e);		/* lock while aborting */
    storeNegativeCache(e);
    storeReleaseRequest(e);
    e->store_status = STORE_ABORTED;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    /* No DISK swap for negative cached object */
    e->swap_status = SWAPOUT_NONE;
    /*
     * We assign an object length here.  The only other place we assign
     * the object length is in storeComplete()
     */
    mem->object_sz = mem->inmem_hi;
    /* Notify the server side */
    if (cbflag && mem->abort.callback) {
	callback = mem->abort.callback;
	data = mem->abort.data;
	mem->abort.callback = NULL;
	mem->abort.data = NULL;
	callback(data);
    }
    /* Notify the client side */
    InvokeHandlers(e);
    /* Do we need to close the swapout file? */
    /* Not if we never started swapping out */
    /* But we may need to cancel an open/stat in progress if using ASYNC */
#if USE_ASYNC_IO
    aioCancel(-1, e);
#endif
    if (e->swap_file_number > -1) {
#if USE_ASYNC_IO
	/* Need to cancel any pending ASYNC writes right now */
	if (mem->swapout.fd >= 0)
	    aioCancel(mem->swapout.fd, NULL);
#endif
	/* we have to close the disk file if there is no write pending */
	if (!storeSwapOutWriteQueued(mem))
	    storeSwapOutFileClose(e);
    }
    storeUnlockObject(e);	/* unlock */
}

/* Clear Memory storage to accommodate the given object len */
static void
storeGetMemSpace(int size)
{
    StoreEntry *e = NULL;
    int released = 0;
    static time_t last_check = 0;
    int pages_needed;
    dlink_node *m;
    dlink_node *head;
    dlink_node *prev = NULL;
    if (squid_curtime == last_check)
	return;
    last_check = squid_curtime;
    pages_needed = (size / SM_PAGE_SIZE) + 1;
    if (memInUse(MEM_STMEM_BUF) + pages_needed < store_pages_high)
	return;
    if (store_rebuilding)
	return;
    debug(20, 2) ("storeGetMemSpace: Starting, need %d pages\n", pages_needed);
    head = inmem_list.head;
    for (m = inmem_list.tail; m; m = prev) {
	if (m == head)
	    break;
	prev = m->prev;
	e = m->data;
	if (storeEntryLocked(e)) {
	    dlinkDelete(m, &inmem_list);
	    dlinkAdd(e, m, &inmem_list);
	    continue;
	}
	released++;
	storePurgeMem(e);
	if (memInUse(MEM_STMEM_BUF) + pages_needed < store_pages_high)
	    break;
    }
    debug(20, 3) ("storeGetMemSpace stats:\n");
    debug(20, 3) ("  %6d HOT objects\n", hot_obj_count);
    debug(20, 3) ("  %6d were released\n", released);
}

/* The maximum objects to scan for maintain storage space */
#define MAINTAIN_MAX_SCAN	1024
#define MAINTAIN_MAX_REMOVE	64

/* 
 * This routine is to be called by main loop in main.c.
 * It removes expired objects on only one bucket for each time called.
 * returns the number of objects removed
 *
 * This should get called 1/s from main().
 */
void
storeMaintainSwapSpace(void *datanotused)
{
    dlink_node *m;
    dlink_node *prev = NULL;
    StoreEntry *e = NULL;
    int scanned = 0;
    int locked = 0;
    int expired = 0;
    int max_scan;
    int max_remove;
    static time_t last_warn_time = 0;
    /* We can't delete objects while rebuilding swap */
    if (store_rebuilding) {
	eventAdd("MaintainSwapSpace", storeMaintainSwapSpace, NULL, 1.0, 1);
	return;
    } else if (store_swap_size < store_swap_mid) {
	max_scan = 100;
	max_remove = 8;
	eventAdd("MaintainSwapSpace", storeMaintainSwapSpace, NULL, 1.0, 1);
    } else if (store_swap_size < store_swap_high) {
	max_scan = 200;
	max_remove = 8;
	eventAdd("MaintainSwapSpace", storeMaintainSwapSpace, NULL, 0.1, 1);
    } else {
	max_scan = 500;
	max_remove = 32;
	eventAdd("MaintainSwapSpace", storeMaintainSwapSpace, NULL, 0.0, 1);
    }
    debug(20, 3) ("storeMaintainSwapSpace\n");
    for (m = store_list.tail; m; m = prev) {
	prev = m->prev;
	e = m->data;
	scanned++;
	if (storeEntryLocked(e)) {
	    /*
	     * If there is a locked entry at the tail of the LRU list,
	     * move it to the beginning to get it out of the way.
	     * Theoretically, we might have all locked objects at the
	     * tail, and then we'll never remove anything here and the
	     * LRU age will go to zero.
	     */
	    if (memInUse(MEM_STOREENTRY) > max_scan) {
		dlinkDelete(&e->lru, &store_list);
		dlinkAdd(e, &e->lru, &store_list);
	    }
	    locked++;
	} else if (storeCheckExpired(e)) {
	    expired++;
	    storeRelease(e);
	}
	if (expired >= max_remove)
	    break;
	if (scanned >= max_scan)
	    break;
    }
    debug(20, 3) ("storeMaintainSwapSpace stats:\n");
    debug(20, 3) ("  %6d objects\n", memInUse(MEM_STOREENTRY));
    debug(20, 3) ("  %6d were scanned\n", scanned);
    debug(20, 3) ("  %6d were locked\n", locked);
    debug(20, 3) ("  %6d were expired\n", expired);
    if (store_swap_size < Config.Swap.maxSize)
	return;
    if (squid_curtime - last_warn_time < 10)
	return;
    debug(20, 0) ("WARNING: Disk space over limit: %d KB > %d KB\n",
	store_swap_size, Config.Swap.maxSize);
    last_warn_time = squid_curtime;
}


/* release an object from a cache */
/* return number of objects released. */
void
storeRelease(StoreEntry * e)
{
    debug(20, 3) ("storeRelease: Releasing: '%s'\n", storeKeyText(e->key));
    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */
    if (storeEntryLocked(e)) {
	storeExpireNow(e);
	debug(20, 3) ("storeRelease: Only setting RELEASE_REQUEST bit\n");
	storeReleaseRequest(e);
	return;
    }
    if (store_rebuilding) {
	debug(20, 2) ("storeRelease: Delaying release until store is rebuilt: '%s'\n",
	    storeUrl(e));
	storeExpireNow(e);
	storeReleaseRequest(e);
	return;
    }
#if USE_ASYNC_IO
    /*
     * Make sure all forgotten async ops are cancelled
     */
    aioCancel(-1, e);
#endif
    storeLog(STORE_LOG_RELEASE, e);
    if (e->swap_file_number > -1) {
	storeUnlinkFileno(e->swap_file_number);
	storeDirMapBitReset(e->swap_file_number);
	if (e->swap_status == SWAPOUT_DONE)
	    if (EBIT_TEST(e->flags, ENTRY_VALIDATED))
		storeDirUpdateSwapSize(e->swap_file_number, e->swap_file_sz, -1);
	if (!EBIT_TEST(e->flags, KEY_PRIVATE))
	    storeDirSwapLog(e, SWAP_LOG_DEL);
    }
    storeSetMemStatus(e, NOT_IN_MEMORY);
    destroy_StoreEntry(e);
}

/* return 1 if a store entry is locked */
static int
storeEntryLocked(const StoreEntry * e)
{
    if (e->lock_count)
	return 1;
    if (e->swap_status == SWAPOUT_OPENING)
	return 1;
    if (e->swap_status == SWAPOUT_WRITING)
	return 1;
    if (e->store_status == STORE_PENDING)
	return 1;
    if (EBIT_TEST(e->flags, ENTRY_SPECIAL))
	return 1;
    return 0;
}

static int
storeEntryValidLength(const StoreEntry * e)
{
    int diff;
    const HttpReply *reply;
    assert(e->mem_obj != NULL);
    reply = e->mem_obj->reply;
    debug(20, 3) ("storeEntryValidLength: Checking '%s'\n", storeKeyText(e->key));
    debug(20, 5) ("storeEntryValidLength:     object_len = %d\n",
	objectLen(e));
    debug(20, 5) ("storeEntryValidLength:         hdr_sz = %d\n",
	reply->hdr_sz);
    debug(20, 5) ("storeEntryValidLength: content_length = %d\n",
	reply->content_length);
    if (reply->content_length < 0) {
	debug(20, 5) ("storeEntryValidLength: Unspecified content length: %s\n",
	    storeKeyText(e->key));
	return 1;
    }
    if (reply->hdr_sz == 0) {
	debug(20, 5) ("storeEntryValidLength: Zero header size: %s\n",
	    storeKeyText(e->key));
	return 1;
    }
    if (e->mem_obj->method == METHOD_HEAD) {
	debug(20, 5) ("storeEntryValidLength: HEAD request: %s\n",
	    storeKeyText(e->key));
	return 1;
    }
    if (reply->sline.status == HTTP_NOT_MODIFIED)
	return 1;
    if (reply->sline.status == HTTP_NO_CONTENT)
	return 1;
    diff = reply->hdr_sz + reply->content_length - objectLen(e);
    if (diff == 0)
	return 1;
    debug(20, 3) ("storeEntryValidLength: %d bytes too %s; '%s'\n",
	diff < 0 ? -diff : diff,
	diff < 0 ? "small" : "big",
	storeKeyText(e->key));
    return 0;
}

static void
storeInitHashValues(void)
{
    int i;
    /* Calculate size of hash table (maximum currently 64k buckets).  */
    i = Config.Swap.maxSize / Config.Store.avgObjectSize;
    debug(20, 1) ("Swap maxSize %d KB, estimated %d objects\n",
	Config.Swap.maxSize, i);
    i /= Config.Store.objectsPerBucket;
    debug(20, 1) ("Target number of buckets: %d\n", i);
    /* ideally the full scan period should be configurable, for the
     * moment it remains at approximately 24 hours.  */
    store_hash_buckets = storeKeyHashBuckets(i);
    store_maintain_rate = 86400 / store_hash_buckets;
    assert(store_maintain_rate > 0);
    debug(20, 1) ("Using %d Store buckets, replacement runs every %d second%s\n",
	store_hash_buckets,
	store_maintain_rate,
	store_maintain_rate == 1 ? null_string : "s");
    debug(20, 1) ("Max Mem  size: %d KB\n", Config.Mem.maxSize >> 10);
    debug(20, 1) ("Max Swap size: %d KB\n", Config.Swap.maxSize);
}

void
storeInit(void)
{
    storeKeyInit();
    storeInitHashValues();
    store_table = hash_create(storeKeyHashCmp,
	store_hash_buckets, storeKeyHashHash);
    storeDigestInit();
    storeLogOpen();
    if (storeVerifyCacheDirs() < 0) {
	xstrncpy(tmp_error_buf,
	    "\tFailed to verify one of the swap directories, Check cache.log\n"
	    "\tfor details.  Run 'squid -z' to create swap directories\n"
	    "\tif needed, or if running Squid for the first time.",
	    ERROR_BUF_SZ);
	fatal(tmp_error_buf);
    }
    storeDirOpenSwapLogs();
    store_list.head = store_list.tail = NULL;
    inmem_list.head = inmem_list.tail = NULL;
    storeRebuildStart();
    cachemgrRegister("storedir",
	"Store Directory Stats",
	storeDirStats, 0, 1);
    cachemgrRegister("store_check_cachable_stats",
	"storeCheckCachable() Stats",
	storeCheckCachableStats, 0, 1);
}

void
storeConfigure(void)
{
    int store_mem_high = 0;
    int store_mem_low = 0;
    store_mem_high = (long) (Config.Mem.maxSize / 100) *
	Config.Mem.highWaterMark;
    store_mem_low = (long) (Config.Mem.maxSize / 100) *
	Config.Mem.lowWaterMark;

    store_swap_high = (long) (((float) Config.Swap.maxSize *
	    (float) Config.Swap.highWaterMark) / (float) 100);
    store_swap_low = (long) (((float) Config.Swap.maxSize *
	    (float) Config.Swap.lowWaterMark) / (float) 100);
    store_swap_mid = (store_swap_high >> 1) + (store_swap_low >> 1);

    store_pages_high = store_mem_high / SM_PAGE_SIZE;
    store_pages_low = store_mem_low / SM_PAGE_SIZE;
}

static int
storeKeepInMemory(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
    if (mem->data_hdr.head == NULL)
	return 0;
    return mem->inmem_lo == 0;
}

static int
storeCheckExpired(const StoreEntry * e)
{
    if (storeEntryLocked(e))
	return 0;
    if (EBIT_TEST(e->flags, RELEASE_REQUEST))
	return 1;
    if (EBIT_TEST(e->flags, ENTRY_NEGCACHED) && squid_curtime >= e->expires)
	return 1;
    if (squid_curtime - e->lastref > storeExpiredReferenceAge())
	return 1;
    return 0;
}

/* 
 * storeExpiredReferenceAge
 *
 * The LRU age is scaled exponentially between 1 minute and
 * Config.referenceAge , when store_swap_low < store_swap_size <
 * store_swap_high.  This keeps store_swap_size within the low and high
 * water marks.  If the cache is very busy then store_swap_size stays
 * closer to the low water mark, if it is not busy, then it will stay
 * near the high water mark.  The LRU age value can be examined on the
 * cachemgr 'info' page.
 */
time_t
storeExpiredReferenceAge(void)
{
    double x;
    double z;
    time_t age;
    x = (double) (store_swap_high - store_swap_size) / (store_swap_high - store_swap_low);
    x = x < 0.0 ? 0.0 : x > 1.0 ? 1.0 : x;
    z = pow((double) (Config.referenceAge / 60), x);
    age = (time_t) (z * 60.0);
    if (age < 60)
	age = 60;
    else if (age > 31536000)
	age = 31536000;
    return age;
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
    hashFreeItems(store_table, destroy_StoreEntry);
    hashFreeMemory(store_table);
    store_table = NULL;
    if (store_digest)
	cacheDigestDestroy(store_digest);
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
    if (e->store_status == STORE_ABORTED)
	return 0;
    return 1;
}

void
storeTimestampsSet(StoreEntry * entry)
{
    time_t served_date = -1;
    const HttpReply *reply = entry->mem_obj->reply;
    served_date = reply->date;
    if (served_date < 0)
	served_date = squid_curtime;
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
storeMemObjectDump(MemObject * mem)
{
    debug(20, 1) ("MemObject->data.head: %p\n",
	mem->data_hdr.head);
    debug(20, 1) ("MemObject->data.tail: %p\n",
	mem->data_hdr.tail);
    debug(20, 1) ("MemObject->data.origin_offset: %d\n",
	mem->data_hdr.origin_offset);
    debug(20, 1) ("MemObject->start_ping: %d.%06d\n",
	(int) mem->start_ping.tv_sec,
	(int) mem->start_ping.tv_usec);
    debug(20, 1) ("MemObject->inmem_hi: %d\n",
	(int) mem->inmem_hi);
    debug(20, 1) ("MemObject->inmem_lo: %d\n",
	(int) mem->inmem_lo);
    debug(20, 1) ("MemObject->clients: %p\n",
	mem->clients);
    debug(20, 1) ("MemObject->nclients: %d\n",
	mem->nclients);
    debug(20, 1) ("MemObject->swapout.fd: %d\n",
	mem->swapout.fd);
    debug(20, 1) ("MemObject->reply: %p\n",
	mem->reply);
    debug(20, 1) ("MemObject->request: %p\n",
	mem->request);
    debug(20, 1) ("MemObject->log_url: %p %s\n",
	mem->log_url,
	checkNullString(mem->log_url));
}

void
storeEntryDump(StoreEntry * e, int l)
{
    debug(20, l) ("StoreEntry->key: %s\n", storeKeyText(e->key));
    debug(20, l) ("StoreEntry->next: %p\n", e->next);
    debug(20, l) ("StoreEntry->mem_obj: %p\n", e->mem_obj);
    debug(20, l) ("StoreEntry->timestamp: %d\n", (int) e->timestamp);
    debug(20, l) ("StoreEntry->lastref: %d\n", (int) e->lastref);
    debug(20, l) ("StoreEntry->expires: %d\n", (int) e->expires);
    debug(20, l) ("StoreEntry->lastmod: %d\n", (int) e->lastmod);
    debug(20, l) ("StoreEntry->swap_file_sz: %d\n", (int) e->swap_file_sz);
    debug(20, l) ("StoreEntry->refcount: %d\n", e->refcount);
    debug(20, l) ("StoreEntry->flags: %s\n", storeEntryFlags(e));
    debug(20, l) ("StoreEntry->swap_file_number: %d\n", (int) e->swap_file_number);
    debug(20, l) ("StoreEntry->lock_count: %d\n", (int) e->lock_count);
    debug(20, l) ("StoreEntry->mem_status: %d\n", (int) e->mem_status);
    debug(20, l) ("StoreEntry->ping_status: %d\n", (int) e->ping_status);
    debug(20, l) ("StoreEntry->store_status: %d\n", (int) e->store_status);
    debug(20, l) ("StoreEntry->swap_status: %d\n", (int) e->swap_status);
}

/* NOTE, this function assumes only two mem states */
void
storeSetMemStatus(StoreEntry * e, int new_status)
{
    MemObject *mem = e->mem_obj;
    if (new_status == e->mem_status)
	return;
    assert(mem != NULL);
    if (new_status == IN_MEMORY) {
	assert(mem->inmem_lo == 0);
	dlinkAdd(e, &mem->lru, &inmem_list);
	hot_obj_count++;
    } else {
	dlinkDelete(&mem->lru, &inmem_list);
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
    e->mem_obj = new_MemObject(url, log_url);
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
    storeCheckSwapOut(e);
}

void
storeUnlinkFileno(int fileno)
{
    debug(20, 5) ("storeUnlinkFileno: %08X\n", fileno);
#if USE_ASYNC_IO
    safeunlink(storeSwapFullPath(fileno, NULL), 1);
#else
    unlinkdUnlink(storeSwapFullPath(fileno, NULL));
#endif
}

int
objectLen(const StoreEntry * e)
{
    assert(e->mem_obj != NULL);
    return e->mem_obj->object_sz;
}

int
contentLen(const StoreEntry * e)
{
    assert(e->mem_obj != NULL);
    assert(e->mem_obj->reply != NULL);
    return e->mem_obj->object_sz - e->mem_obj->reply->hdr_sz;
}

HttpReply *
storeEntryReply(StoreEntry * e)
{
    if (NULL == e)
	return NULL;
    if (NULL == e->mem_obj)
	return NULL;
    return e->mem_obj->reply;
}
