
/*
 * $Id: store.cc,v 1.372 1998/02/03 03:08:51 wessels Exp $
 *
 * DEBUG: section 20    Storeage Manager
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

#define REBUILD_TIMESTAMP_DELTA_MAX 2

#define STORE_IN_MEM_BUCKETS		(229)

static char *storeLogTags[] =
{
    "CREATE",
    "SWAPIN",
    "SWAPOUT",
    "RELEASE"
};

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

/* Static Functions */
static int storeCheckExpired(const StoreEntry *, int flag);
static int storeEntryLocked(const StoreEntry *);
static int storeEntryValidLength(const StoreEntry *);
static void storeGetMemSpace(int);
static void storeHashDelete(StoreEntry *);
static MemObject *new_MemObject(const char *, const char *);
static void destroy_MemObject(StoreEntry *);
static void destroy_MemObjectData(MemObject *);
static void destroy_StoreEntry(StoreEntry *);
static void storePurgeMem(StoreEntry *);
static void storeSetPrivateKey(StoreEntry *);
#if OLD_CODE
static STVLDCB storeCleanupComplete;
#endif
static unsigned int getKeyCounter(void);
static int storeKeepInMemory(const StoreEntry *);

static dlink_list inmem_list;
static dlink_list all_list;

static int store_pages_high = 0;
static int store_pages_low = 0;

/* current file name, swap file, use number as a filename */
static int store_swap_high = 0;
static int store_swap_low = 0;
static int storelog_fd = -1;

/* expiration parameters and stats */
static int store_maintain_rate;
static int store_maintain_buckets;

#if OLD_CODE
/* outstanding cleanup validations */
static int outvalid = 0;
#endif

static MemObject *
new_MemObject(const char *url, const char *log_url)
{
    MemObject *mem = memAllocate(MEM_MEMOBJECT, 1);
    mem->reply = memAllocate(MEM_HTTP_REPLY, 1);
    mem->reply->date = -2;
    mem->reply->expires = -2;
    mem->reply->last_modified = -2;
    mem->reply->content_length = -1;
    mem->url = xstrdup(url);
    mem->log_url = xstrdup(log_url);
    mem->swapout.fd = -1;
    meta_data.misc += strlen(log_url);
    debug(20, 3) ("new_MemObject: returning %p\n", mem);
    return mem;
}

StoreEntry *
new_StoreEntry(int mem_obj_flag, const char *url, const char *log_url)
{
    StoreEntry *e = NULL;
    e = memAllocate(MEM_STOREENTRY, 1);
    if (mem_obj_flag)
	e->mem_obj = new_MemObject(url, log_url);
    debug(20, 3) ("new_StoreEntry: returning %p\n", e);
    return e;
}

static void
destroy_MemObject(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    debug(20, 3) ("destroy_MemObject: destroying %p\n", mem);
    assert(mem->swapout.fd == -1);
    destroy_MemObjectData(mem);
    meta_data.misc -= strlen(mem->log_url);
#if USE_ASYNC_IO
    while (mem->clients != NULL)
	storeUnregister(e, mem->clients->callback_data);
#endif
    assert(mem->clients == NULL);
    safe_free(mem->swapout.meta_buf);
    memFree(MEM_HTTP_REPLY, mem->reply);
    safe_free(mem->url);
    safe_free(mem->log_url);
    requestUnlink(mem->request);
    mem->request = NULL;
    memFree(MEM_MEMOBJECT, mem);
}

static void
destroy_StoreEntry(StoreEntry * e)
{
    debug(20, 3) ("destroy_StoreEntry: destroying %p\n", e);
    assert(e != NULL);
    if (e->mem_obj)
	destroy_MemObject(e);
    storeHashDelete(e);
    assert(e->key == NULL);
    xfree(e);
}

static void
destroy_MemObjectData(MemObject * mem)
{
    debug(20, 3) ("destroy_MemObjectData: destroying %p, %d bytes\n",
	mem->data, mem->inmem_hi);
    if (mem->data) {
	stmemFree(mem->data);
	mem->data = NULL;
    }
    mem->inmem_hi = 0;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

void
storeHashInsert(StoreEntry * e, const cache_key * key)
{
    debug(20, 3) ("storeHashInsert: Inserting Entry %p key '%s'\n",
	e, storeKeyText(key));
    e->key = storeKeyDup(key);
    hash_join(store_table, (hash_link *) e);
    dlinkAdd(e, &e->lru, &all_list);
}

static void
storeHashDelete(StoreEntry * e)
{
    hash_remove_link(store_table, (hash_link *) e);
    dlinkDelete(&e->lru, &all_list);
    storeKeyFree(e->key);
    e->key = NULL;
}

/* -------------------------------------------------------------------------- */

void
storeLog(int tag, const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    MemObject *mem = e->mem_obj;
    struct _http_reply *reply;
    if (storelog_fd < 0)
	return;
    if (mem == NULL)
	return;
    if (mem->log_url == NULL) {
	debug(20, 1) ("storeLog: NULL log_url for %s\n", mem->url);
	storeMemObjectDump(mem);
	mem->log_url = xstrdup(mem->url);
    }
    reply = mem->reply;
    snprintf(logmsg, MAX_URL << 1, "%9d.%03d %-7s %08X %4d %9d %9d %9d %s %d/%d %s %s\n",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec / 1000,
	storeLogTags[tag],
	e->swap_file_number,
	reply->code,
	(int) reply->date,
	(int) reply->last_modified,
	(int) reply->expires,
	reply->content_type[0] ? reply->content_type : "unknown",
	reply->content_length,
	(int) (mem->inmem_hi - mem->reply->hdr_sz),
	RequestMethodStr[mem->method],
	mem->log_url);
    file_write(storelog_fd,
	-1,
	xstrdup(logmsg),
	strlen(logmsg),
	NULL,
	NULL,
	xfree);
}


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
    e->mem_obj = NULL;
    if (e->swap_status != SWAPOUT_DONE)
	storeRelease(e);
}

void
storeLockObject(StoreEntry * e)
{
    if (e->lock_count++ == 0) {
	dlinkDelete(&e->lru, &all_list);
	dlinkAdd(e, &e->lru, &all_list);
    }
    debug(20, 3) ("storeLockObject: key '%s' count=%d\n",
	storeKeyText(e->key), (int) e->lock_count);
    e->lastref = squid_curtime;
}

void
storeReleaseRequest(StoreEntry * e)
{
    if (EBIT_TEST(e->flag, RELEASE_REQUEST))
	return;
    assert(storeEntryLocked(e));
    debug(20, 3) ("storeReleaseRequest: '%s'\n", storeKeyText(e->key));
    EBIT_SET(e->flag, RELEASE_REQUEST);
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
	assert(!EBIT_TEST(e->flag, ENTRY_DISPATCHED));
	EBIT_SET(e->flag, RELEASE_REQUEST);
    }
    assert(storePendingNClients(e) == 0);
    if (EBIT_TEST(e->flag, RELEASE_REQUEST))
	storeRelease(e);
    else if (storeKeepInMemory(e)) {
	storeSetMemStatus(e, IN_MEMORY);
	requestUnlink(e->mem_obj->request);
	e->mem_obj->request = NULL;
    } else
	storePurgeMem(e);
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

static unsigned int
getKeyCounter(void)
{
    static unsigned int key_counter = 0;
    if (++key_counter == (1 << 24))
	key_counter = 1;
    return key_counter;
}

static void
storeSetPrivateKey(StoreEntry * e)
{
    const cache_key *newkey;
    MemObject *mem = e->mem_obj;
    if (e->key && EBIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already private */
    if (e->key)
	storeHashDelete(e);
    if (mem != NULL) {
	mem->reqnum = getKeyCounter();
	newkey = storeKeyPrivate(mem->url, mem->method, mem->reqnum);
    } else {
	newkey = storeKeyPrivate("JUNK", METHOD_NONE, getKeyCounter());
    }
    assert(hash_lookup(store_table, newkey) == NULL);
    storeHashInsert(e, newkey);
    EBIT_SET(e->flag, KEY_PRIVATE);
}

void
storeSetPublicKey(StoreEntry * e)
{
    StoreEntry *e2 = NULL;
    const cache_key *newkey;
    MemObject *mem = e->mem_obj;
    if (e->key && !EBIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already public */
    assert(mem);
    newkey = storeKeyPublic(mem->url, mem->method);
    if ((e2 = (StoreEntry *) hash_lookup(store_table, newkey))) {
	debug(20, 3) ("storeSetPublicKey: Making old '%s' private.\n", mem->url);
	storeSetPrivateKey(e2);
	storeRelease(e2);
	newkey = storeKeyPublic(mem->url, mem->method);
    }
    if (e->key)
	storeHashDelete(e);
    storeHashInsert(e, newkey);
    EBIT_CLR(e->flag, KEY_PRIVATE);
}

StoreEntry *
storeCreateEntry(const char *url, const char *log_url, int flags, method_t method)
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    debug(20, 3) ("storeCreateEntry: '%s' icp flags=%x\n", url, flags);

    e = new_StoreEntry(STORE_ENTRY_WITH_MEMOBJ, url, log_url);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    mem->method = method;
    if (neighbors_do_private_keys || !EBIT_TEST(flags, REQ_HIERARCHICAL))
	storeSetPrivateKey(e);
    else
	storeSetPublicKey(e);
    if (EBIT_TEST(flags, REQ_CACHABLE)) {
	EBIT_SET(e->flag, ENTRY_CACHABLE);
	EBIT_CLR(e->flag, RELEASE_REQUEST);
    } else {
	EBIT_CLR(e->flag, ENTRY_CACHABLE);
	storeReleaseRequest(e);
    }
    if (EBIT_TEST(flags, REQ_HIERARCHICAL))
	EBIT_SET(e->flag, HIERARCHICAL);
    else
	EBIT_CLR(e->flag, HIERARCHICAL);
    e->store_status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_NONE;
    e->swap_file_number = -1;
    mem->data = memAllocate(MEM_MEM_HDR, 1);
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = 0;		/* set in storeTimestampsSet() */
    e->ping_status = PING_NONE;
    EBIT_SET(e->flag, ENTRY_VALIDATED);
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
	stmemAppend(mem->data, buf, len);
	mem->inmem_hi += len;
    }
    if (EBIT_TEST(e->flag, DELAY_SENDING))
	return;
    InvokeHandlers(e);
    storeCheckSwapOut(e);
}

#ifdef __STDC__
void
storeAppendPrintf(StoreEntry * e, const char *fmt,...)
{
    va_list args;
    LOCAL_ARRAY(char, buf, 4096);
    va_start(args, fmt);
#else
void
storeAppendPrintf(va_alist)
     va_dcl
{
    va_list args;
    StoreEntry *e = NULL;
    const char *fmt = NULL;
    LOCAL_ARRAY(char, buf, 4096);
    va_start(args);
    e = va_arg(args, StoreEntry *);
    fmt = va_arg(args, char *);
#endif
    buf[0] = '\0';
    vsnprintf(buf, 4096, fmt, args);
    storeAppend(e, buf, strlen(buf));
    va_end(args);
}

int
storeCheckCachable(StoreEntry * e)
{
#if CACHE_ALL_METHODS
    if (e->mem_obj->method != METHOD_GET) {
	debug(20, 2) ("storeCheckCachable: NO: non-GET method\n");
    } else
#endif
    if (!EBIT_TEST(e->flag, ENTRY_CACHABLE)) {
	debug(20, 2) ("storeCheckCachable: NO: not cachable\n");
    } else if (EBIT_TEST(e->flag, RELEASE_REQUEST)) {
	debug(20, 2) ("storeCheckCachable: NO: release requested\n");
    } else if (e->store_status == STORE_OK && EBIT_TEST(e->flag, ENTRY_BAD_LENGTH)) {
	debug(20, 2) ("storeCheckCachable: NO: wrong content-length\n");
    } else if (EBIT_TEST(e->flag, ENTRY_NEGCACHED)) {
	debug(20, 2) ("storeCheckCachable: NO: negative cached\n");
	return 0;		/* avoid release call below */
    } else if (e->mem_obj->inmem_hi > Config.Store.maxObjectSize) {
	debug(20, 2) ("storeCheckCachable: NO: too big\n");
    } else if (EBIT_TEST(e->flag, KEY_PRIVATE)) {
	debug(20, 3) ("storeCheckCachable: NO: private key\n");
    } else {
	return 1;
    }
    storeReleaseRequest(e);
    EBIT_CLR(e->flag, ENTRY_CACHABLE);
    return 0;
}

/* Complete transfer into the local cache.  */
void
storeComplete(StoreEntry * e)
{
    debug(20, 3) ("storeComplete: '%s'\n", storeKeyText(e->key));
    e->object_len = e->mem_obj->inmem_hi;
    e->store_status = STORE_OK;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!storeEntryValidLength(e))
	EBIT_SET(e->flag, ENTRY_BAD_LENGTH);
    InvokeHandlers(e);
    storeCheckSwapOut(e);
}

/*
 * Someone wants to abort this transfer.  Set the reason in the
 * request structure, call the server-side callback and mark the
 * entry for releasing 
 */
void
storeAbort(StoreEntry * e, int cbflag)
{
    MemObject *mem = e->mem_obj;
    assert(e->store_status == STORE_PENDING);
    assert(mem != NULL);
    debug(20, 6) ("storeAbort: %s\n", storeKeyText(e->key));
    storeNegativeCache(e);
    storeReleaseRequest(e);
    e->store_status = STORE_ABORTED;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    /* No DISK swap for negative cached object */
    e->swap_status = SWAPOUT_NONE;
    /* We assign an object length here--The only other place we assign the
     * object length is in storeComplete() */
    e->object_len = mem->inmem_hi;
    /* Notify the server side */
    if (cbflag && mem->abort.callback) {
	mem->abort.callback(mem->abort.data);
	mem->abort.callback = NULL;
    }
    /* Notify the client side */
    InvokeHandlers(e);
    /* Do we need to close the swapout file? */
    /* Not if we never started swapping out */
    /* But we may need to cancel an open/stat in progress if using ASYNC */
#if USE_ASYNC_IO
    aioCancel(-1, e);
#endif
    if (e->swap_file_number == -1)
	return;
#if USE_ASYNC_IO
    /* Need to cancel any pending ASYNC writes right now */
    if (mem->swapout.fd >= 0)
	aioCancel(mem->swapout.fd, NULL);
#endif
    /* but dont close if a disk write is queued, the handler will close up */
    if (mem->swapout.queue_offset > mem->swapout.done_offset)
	return;
    /* we do */
    storeSwapOutFileClose(e);
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
    for (m = inmem_list.tail; m; m = prev) {
	prev = m->prev;
	e = m->data;
	if (storeEntryLocked(e))
	    continue;
	released++;
	storeRelease(e);
	if (memInUse(MEM_STMEM_BUF) + pages_needed < store_pages_low)
	    break;
    }
    debug(20, 3) ("storeGetMemSpace stats:\n");
    debug(20, 3) ("  %6d HOT objects\n", meta_data.hot_vm);
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
    int bigclean = 0;
    int level = 3;
    static time_t last_warn_time = 0;
    eventAdd("storeMaintainSwapSpace", storeMaintainSwapSpace, NULL, 1);
    /* We can't delete objects while rebuilding swap */
    if (store_rebuilding)
	return;

    if (store_swap_size > store_swap_high)
	bigclean = 1;
    if (store_swap_size > Config.Swap.maxSize)
	bigclean = 1;

    if (bigclean) {
	max_scan = 2500;
	max_remove = 250;
    } else {
	return;
    }
    debug(20, 3) ("storeMaintainSwapSpace\n");
    for (m = all_list.tail; m; m = prev) {
	prev = m->prev;
	e = m->data;
	if (storeEntryLocked(e)) {
	    locked++;
	    continue;
	} else if (bigclean) {
	    expired++;
	    storeRelease(e);
	} else {
	    if (storeCheckExpired(e, 1)) {
		expired++;
		storeRelease(e);
	    }
	}
	if (expired > max_remove)
	    break;
	if (++scanned > max_scan)
	    break;
    }
    if (bigclean)
	level = 1;
    debug(20, level) ("storeMaintainSwapSpace stats:\n");
    debug(20, level) ("  %6d objects\n", memInUse(MEM_STOREENTRY));
    debug(20, level) ("  %6d were scanned\n", scanned);
    debug(20, level) ("  %6d were locked\n", locked);
    debug(20, level) ("  %6d were expired\n", expired);
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
#if USE_ASYNC_IO
    aioCancel(-1, e);		/* Make sure all forgotten async ops are cancelled */
#else
    if (store_rebuilding) {
	debug(20, 2) ("storeRelease: Delaying release until store is rebuilt: '%s'\n",
	    storeUrl(e));
	storeExpireNow(e);
	storeSetPrivateKey(e);
	EBIT_SET(e->flag, RELEASE_REQUEST);
	e->object_len = -(e->object_len);
	storeDirSwapLog(e);
	e->object_len = -(e->object_len);
	return;
    }
#endif
    storeLog(STORE_LOG_RELEASE, e);
    if (e->swap_file_number > -1) {
#if MONOTONIC_STORE
#if USE_ASYNC_IO
	safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
#else
	unlinkdUnlink(storeSwapFullPath(e->swap_file_number, NULL));
#endif
#else
	storePutUnusedFileno(e);
#endif
	if (e->swap_status == SWAPOUT_DONE)
	    storeDirUpdateSwapSize(e->swap_file_number, e->object_len, -1);
	e->object_len = -(e->object_len);
	storeDirSwapLog(e);
	e->object_len = -(e->object_len);
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
    if (EBIT_TEST(e->flag, ENTRY_SPECIAL))
	return 1;
    return 0;
}

static int
storeEntryValidLength(const StoreEntry * e)
{
    int diff;
    int hdr_sz;
    int content_length;
    assert(e->mem_obj != NULL);
    hdr_sz = e->mem_obj->reply->hdr_sz;
    content_length = e->mem_obj->reply->content_length;

    debug(20, 3) ("storeEntryValidLength: Checking '%s'\n", storeKeyText(e->key));
    debug(20, 5) ("storeEntryValidLength:     object_len = %d\n", e->object_len);
    debug(20, 5) ("storeEntryValidLength:         hdr_sz = %d\n", hdr_sz);
    debug(20, 5) ("storeEntryValidLength: content_length = %d\n", content_length);

    if (content_length < 0) {
	debug(20, 5) ("storeEntryValidLength: Unspecified content length: %s\n",
	    storeKeyText(e->key));
	return 1;
    }
    if (hdr_sz == 0) {
	debug(20, 5) ("storeEntryValidLength: Zero header size: %s\n",
	    storeKeyText(e->key));
	return 1;
    }
    if (e->mem_obj->method == METHOD_HEAD) {
	debug(20, 5) ("storeEntryValidLength: HEAD request: %s\n",
	    storeKeyText(e->key));
	return 1;
    }
    if (e->mem_obj->reply->code == HTTP_NOT_MODIFIED)
	return 1;
    if (e->mem_obj->reply->code == HTTP_NO_CONTENT)
	return 1;
    diff = hdr_sz + content_length - e->object_len;
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
    debug(20, 1) ("Using %d Store buckets, maintain %d bucket%s every %d second%s\n",
	store_hash_buckets,
	store_maintain_buckets,
	store_maintain_buckets == 1 ? null_string : "s",
	store_maintain_rate,
	store_maintain_rate == 1 ? null_string : "s");
    debug(20, 1) ("Max Mem  size: %d KB\n", Config.Mem.maxSize >> 10);
    debug(20, 1) ("Max Swap size: %d KB\n", Config.Swap.maxSize);
}

void
storeInit(void)
{
    char *fname = NULL;
    storeInitHashValues();
    store_table = hash_create(storeKeyHashCmp,
	store_hash_buckets, storeKeyHashHash);
    if (strcmp((fname = Config.Log.store), "none") == 0)
	storelog_fd = -1;
    else
	storelog_fd = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL, NULL);
    if (storelog_fd < 0)
	debug(20, 1) ("Store logging disabled\n");
    if (storeVerifyCacheDirs() < 0) {
	xstrncpy(tmp_error_buf,
	    "\tFailed to verify one of the swap directories, Check cache.log\n"
	    "\tfor details.  Run 'squid -z' to create swap directories\n"
	    "\tif needed, or if running Squid for the first time.",
	    ERROR_BUF_SZ);
	fatal(tmp_error_buf);
    }
    if (opt_convert) {
	storeDirOpenSwapLogs();
	storeConvert();
	debug(0, 0) ("DONE Converting. Welcome to %s!\n", version_string);
	storeDirCloseSwapLogs();
	exit(0);
    }
    storeStartRebuildFromDisk();
    all_list.head = all_list.tail = NULL;
    inmem_list.head = inmem_list.tail = NULL;
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

    store_pages_high = store_mem_high / SM_PAGE_SIZE;
    store_pages_low = store_mem_low / SM_PAGE_SIZE;
}

int
urlcmp(const void *url1, const void *url2)
{
    assert(url1 && url2);
    return (strcmp(url1, url2));
}

/*
 *  storeWriteCleanLogs
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
#define CLEAN_BUF_SZ 16384
int
storeWriteCleanLogs(int reopen)
{
    StoreEntry *e = NULL;
    int *fd;
    char *line;
    int n = 0;
    time_t start, stop, r;
    struct stat sb;
    char **cur;
    char **new;
    char **cln;
    int dirn;
    dlink_node *m;
    int linelen;
    char **outbufs;
    int *outbuflens;
    if (store_rebuilding) {
	debug(20, 1) ("Not currently OK to rewrite swap log.\n");
	debug(20, 1) ("storeWriteCleanLogs: Operation aborted.\n");
	storeDirCloseSwapLogs();
	return 0;
    }
    debug(20, 1) ("storeWriteCleanLogs: Starting...\n");
    start = squid_curtime;
    fd = xcalloc(Config.cacheSwap.n_configured, sizeof(int));
    cur = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    new = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    cln = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	fd[dirn] = -1;
	cur[dirn] = xstrdup(storeDirSwapLogFile(dirn, NULL));
	new[dirn] = xstrdup(storeDirSwapLogFile(dirn, ".clean"));
	cln[dirn] = xstrdup(storeDirSwapLogFile(dirn, ".last-clean"));
	unlink(new[dirn]);
	unlink(cln[dirn]);
	fd[dirn] = file_open(new[dirn],
	    O_WRONLY | O_CREAT | O_TRUNC,
	    NULL,
	    NULL,
	    NULL);
	if (fd[dirn] < 0) {
	    debug(50, 0) ("storeWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
	    continue;
	}
#if HAVE_FCHMOD
	if (stat(cur[dirn], &sb) == 0)
	    fchmod(fd[dirn], sb.st_mode);
#endif
    }
    line = xcalloc(1, CLEAN_BUF_SZ);
    outbufs = xcalloc(Config.cacheSwap.n_configured, sizeof(char *));
    outbuflens = xcalloc(Config.cacheSwap.n_configured, sizeof(int));
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	outbufs[dirn] = xcalloc(Config.cacheSwap.n_configured, CLEAN_BUF_SZ);
	outbuflens[dirn] = 0;
    }
    for (m = all_list.tail; m; m = m->prev) {
	e = m->data;
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAPOUT_DONE)
	    continue;
	if (e->object_len <= 0)
	    continue;
	if (EBIT_TEST(e->flag, RELEASE_REQUEST))
	    continue;
	if (EBIT_TEST(e->flag, KEY_PRIVATE))
	    continue;
	dirn = storeDirNumber(e->swap_file_number);
	assert(dirn < Config.cacheSwap.n_configured);
	if (fd[dirn] < 0)
	    continue;
	snprintf(line, CLEAN_BUF_SZ, "%08x %08x %08x %08x %08x %9d %6d %08x %s\n",
	    (int) e->swap_file_number,
	    (int) e->timestamp,
	    (int) e->lastref,
	    (int) e->expires,
	    (int) e->lastmod,
	    e->object_len,
	    e->refcount,
	    e->flag,
	    storeKeyText(e->key));
	linelen = strlen(line);
	/* buffered write */
	if (linelen + outbuflens[dirn] > CLEAN_BUF_SZ - 2) {
	    if (write(fd[dirn], outbufs[dirn], outbuflens[dirn]) < 0) {
		debug(50, 0) ("storeWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
		debug(20, 0) ("storeWriteCleanLogs: Current swap logfile not replaced.\n");
		file_close(fd[dirn]);
		fd[dirn] = -1;
		unlink(cln[dirn]);
		continue;
	    }
	    outbuflens[dirn] = 0;
	}
	strcpy(outbufs[dirn] + outbuflens[dirn], line);
	outbuflens[dirn] += linelen;
	if ((++n & 0x3FFF) == 0) {
	    getCurrentTime();
	    debug(20, 1) ("  %7d lines written so far.\n", n);
	}
    }
    safe_free(line);
    /* flush */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	if (outbuflens[dirn] > 0) {
	    if (write(fd[dirn], outbufs[dirn], outbuflens[dirn]) < 0) {
		debug(50, 0) ("storeWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
		debug(20, 0) ("storeWriteCleanLogs: Current swap logfile not replaced.\n");
		file_close(fd[dirn]);
		fd[dirn] = -1;
		unlink(cln[dirn]);
		continue;
	    }
	}
	safe_free(outbufs[dirn]);
    }
    safe_free(outbufs);
    safe_free(outbuflens);
    /* close */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	file_close(fd[dirn]);
	fd[dirn] = -1;
	if (rename(new[dirn], cur[dirn]) < 0) {
	    debug(50, 0) ("storeWriteCleanLogs: rename failed: %s, %s -> %s\n",
		xstrerror(), new[dirn], cur[dirn]);
	}
    }
    storeDirCloseSwapLogs();
    if (reopen)
	storeDirOpenSwapLogs();
    stop = squid_curtime;
    r = stop - start;
    debug(20, 1) ("  Finished.  Wrote %d lines.\n", n);
    debug(20, 1) ("  Took %d seconds (%6.1lf lines/sec).\n",
	r > 0 ? r : 0, (double) n / (r > 0 ? r : 1));
    /* touch a timestamp file if we're not still validating */
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	if (!store_rebuilding)
	    file_close(file_open(cln[dirn],
		    O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL, NULL));
	safe_free(cur[dirn]);
	safe_free(new[dirn]);
	safe_free(cln[dirn]);
    }
    safe_free(cur);
    safe_free(new);
    safe_free(cln);
    safe_free(fd);
    return n;
}
#undef CLEAN_BUF_SZ

void
storeRotateLog(void)
{
    char *fname = NULL;
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
#ifdef S_ISREG
    struct stat sb;
#endif

    if (storelog_fd > -1) {
	file_close(storelog_fd);
	storelog_fd = -1;
    }
    if ((fname = Config.Log.store) == NULL)
	return;
    if (strcmp(fname, "none") == 0)
	return;
#ifdef S_ISREG
    if (stat(fname, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif

    debug(20, 1) ("storeRotateLog: Rotating.\n");

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	snprintf(from, MAXPATHLEN, "%s.%d", fname, i - 1);
	snprintf(to, MAXPATHLEN, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	snprintf(to, MAXPATHLEN, "%s.%d", fname, 0);
	rename(fname, to);
    }
    storelog_fd = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL, NULL);
    if (storelog_fd < 0) {
	debug(50, 0) ("storeRotateLog: %s: %s\n", fname, xstrerror());
	debug(20, 1) ("Store logging disabled\n");
    }
}

static int
storeKeepInMemory(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
    if (mem->data == NULL)
	return 0;
    return mem->inmem_lo == 0;
}

static int
storeCheckExpired(const StoreEntry * e, int check_lru_age)
{
    if (storeEntryLocked(e))
	return 0;
    if (EBIT_TEST(e->flag, ENTRY_NEGCACHED) && squid_curtime >= e->expires)
	return 1;
    if (!check_lru_age)
	return 0;
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
storeCloseLog(void)
{
    if (storelog_fd >= 0)
	file_close(storelog_fd);
}

void
storeNegativeCache(StoreEntry * e)
{
    e->expires = squid_curtime + Config.negativeTtl;
    EBIT_SET(e->flag, ENTRY_NEGCACHED);
}

void
storeFreeMemory(void)
{
    StoreEntry *e;
    StoreEntry **list;
    int i = 0;
    int j;
    list = xcalloc(memInUse(MEM_STOREENTRY), sizeof(StoreEntry *));
    e = (StoreEntry *) hash_first(store_table);
    while (e && i < memInUse(MEM_STOREENTRY)) {
	*(list + i) = e;
	i++;
	e = (StoreEntry *) hash_next(store_table);
    }
    for (j = 0; j < i; j++)
	destroy_StoreEntry(*(list + j));
    xfree(list);
    hashFreeMemory(store_table);
    store_table = NULL;
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
    if (EBIT_TEST(e->flag, RELEASE_REQUEST))
	return 0;
    if (EBIT_TEST(e->flag, ENTRY_NEGCACHED))
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
    struct _http_reply *reply = entry->mem_obj->reply;
    served_date = reply->date > -1 ? reply->date : squid_curtime;
    entry->expires = reply->expires;
    if (reply->last_modified > -1)
	entry->lastmod = reply->last_modified;
    else
	entry->lastmod = served_date;
    entry->timestamp = served_date;
}

#define FILENO_STACK_SIZE 128
static int fileno_stack[FILENO_STACK_SIZE];

#if !MONOTONIC_STORE
int
storeGetUnusedFileno(void)
{
    int fn;
    if (fileno_stack_count < 1)
	return -1;
    fn = fileno_stack[--fileno_stack_count];
    assert(!storeDirMapBitTest(fn));
    storeDirMapBitSet(fn);
    return fn;
}

void
storePutUnusedFileno(StoreEntry * e)
{
    assert(storeDirMapBitTest(e->swap_file_number));
    storeDirMapBitReset(e->swap_file_number);
    /* If we're still rebuilding the swap state, then we need to avoid the */
    /* race condition where a new object gets pulled in, it expires, gets */
    /* its swapfileno added to the stack, and then that swapfileno gets */
    /* claimed by the rebuild. Must still remove the file though in any */
    /* event to avoid serving up the wrong data.  This will leave us with */
    /* a URL pointing to no file at all, but that's okay since it'll fail */
    /* and get removed later anyway. */
    if (store_rebuilding) {
	if (EBIT_TEST(e->flag, ENTRY_VALIDATED))
	    safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
	return;
    }
    if (fileno_stack_count < FILENO_STACK_SIZE)
	fileno_stack[fileno_stack_count++] = e->swap_file_number;
    else
#if USE_ASYNC_IO
	safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
#else
	unlinkdUnlink(storeSwapFullPath(e->swap_file_number, NULL));
#endif
}
#endif

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
    debug(20, 1) ("MemObject->data: %p\n",
	mem->data);
    debug(20, 1) ("MemObject->start_ping: %d.%06d\n",
	mem->start_ping.tv_sec,
	mem->start_ping.tv_usec);
    debug(20, 1) ("MemObject->inmem_hi: %d\n",
	mem->inmem_hi);
    debug(20, 1) ("MemObject->inmem_lo: %d\n",
	mem->inmem_lo);
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
storeEntryDump(StoreEntry * e)
{
    debug(20, 1) ("StoreEntry->key: %s\n", storeKeyText(e->key));
    debug(20, 1) ("StoreEntry->next: %p\n", e->next);
    debug(20, 1) ("StoreEntry->mem_obj: %p\n", e->mem_obj);
    debug(20, 1) ("StoreEntry->timestamp: %d\n", (int) e->timestamp);
    debug(20, 1) ("StoreEntry->lastref: %d\n", (int) e->lastref);
    debug(20, 1) ("StoreEntry->expires: %d\n", (int) e->expires);
    debug(20, 1) ("StoreEntry->lastmod: %d\n", (int) e->lastmod);
    debug(20, 1) ("StoreEntry->object_len: %d\n", e->object_len);
    debug(20, 1) ("StoreEntry->refcount: %d\n", e->refcount);
    debug(20, 1) ("StoreEntry->flag: %X\n", e->flag);
    debug(20, 1) ("StoreEntry->swap_file_number: %d\n", (int) e->swap_file_number);
    debug(20, 1) ("StoreEntry->lock_count: %d\n", (int) e->lock_count);
    debug(20, 1) ("StoreEntry->mem_status: %d\n", (int) e->mem_status);
    debug(20, 1) ("StoreEntry->ping_status: %d\n", (int) e->ping_status);
    debug(20, 1) ("StoreEntry->store_status: %d\n", (int) e->store_status);
    debug(20, 1) ("StoreEntry->swap_status: %d\n", (int) e->swap_status);
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
	meta_data.hot_vm++;
    } else {
	dlinkDelete(&mem->lru, &inmem_list);
	meta_data.hot_vm--;
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

void
storeCopyNotModifiedReplyHeaders(MemObject * oldmem, MemObject * newmem)
{
    http_reply *oldreply = oldmem->reply;
    http_reply *newreply = newmem->reply;
    oldreply->cache_control = newreply->cache_control;
    oldreply->misc_headers = newreply->misc_headers;
    if (newreply->date > -1)
	oldreply->date = newreply->date;
    if (newreply->last_modified > -1)
	oldreply->last_modified = newreply->last_modified;
    if (newreply->expires > -1)
	oldreply->expires = newreply->expires;
}

/* this just sets DELAY_SENDING */
void
storeBuffer(StoreEntry * e)
{
    EBIT_SET(e->flag, DELAY_SENDING);
}

/* this just clears DELAY_SENDING and Invokes the handlers */
void
storeBufferFlush(StoreEntry * e)
{
    EBIT_CLR(e->flag, DELAY_SENDING);
    InvokeHandlers(e);
}

