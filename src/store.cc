
/*
 * $Id: store.cc,v 1.293 1997/10/17 23:32:38 wessels Exp $
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

#include "squid.h"		/* goes first */

#define REBUILD_TIMESTAMP_DELTA_MAX 2
#define SWAP_BUF		DISK_PAGE_SIZE
#define VM_WINDOW_SZ		DISK_PAGE_SIZE

#define WITH_MEMOBJ	1
#define WITHOUT_MEMOBJ	0

#define STORE_IN_MEM_BUCKETS		(229)

#define STORE_LOG_CREATE	0
#define STORE_LOG_SWAPIN	1
#define STORE_LOG_SWAPOUT	2
#define STORE_LOG_RELEASE	3

#define ENTRY_INMEM_SIZE(X) ((X)->inmem_hi - (X)->inmem_lo)

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

struct storeRebuildState {
    struct _rebuild_dir {
	int dirn;
	FILE *log;
	int speed;
	int clean;
	struct _rebuild_dir *next;
    }           *rebuild_dir;
    int objcount;		/* # objects successfully reloaded */
    int expcount;		/* # objects expired */
    int linecount;		/* # lines parsed from cache logfile */
    int clashcount;		/* # swapfile clashes avoided */
    int dupcount;		/* # duplicates purged */
    int invalid;		/* # bad lines */
    int badflags;		/* # bad e->flags */
    int need_to_validate;
    time_t start;
    time_t stop;
    char *line_in;
    size_t line_in_sz;
};

struct _bucketOrder {
    unsigned int bucket;
    int index;
};

typedef struct storeCleanList {
    char *key;
    struct storeCleanList *next;
} storeCleanList;

typedef void (VCB) _PARAMS((void *));

typedef struct valid_ctrl_t {
    struct stat *sb;
    StoreEntry *e;
    VCB *callback;
    void *callback_data;
} valid_ctrl_t;

typedef struct swapin_ctrl_t {
    StoreEntry *e;
    char *path;
    SIH *callback;
    void *callback_data;
    struct _store_client *sc;
} swapin_ctrl_t;

typedef struct lock_ctrl_t {
    SIH *callback;
    void *callback_data;
    StoreEntry *e;
} lock_ctrl_t;

typedef struct swapout_ctrl_t {
    char *swapfilename;
    int oldswapstatus;
    StoreEntry *e;
} swapout_ctrl_t;

struct _mem_entry {
    StoreEntry *e;
    struct _mem_entry *next;
    struct _mem_entry *prev;
};

/* Static Functions */
static void storeCreateHashTable _PARAMS((int (*)_PARAMS((const char *, const char *))));
static int compareLastRef _PARAMS((StoreEntry **, StoreEntry **));
static int compareBucketOrder _PARAMS((struct _bucketOrder *, struct _bucketOrder *));
static int storeCheckExpired _PARAMS((const StoreEntry *, int flag));
#if OLD_CODE
static int storeCheckPurgeMem _PARAMS((const StoreEntry *));
static int compareSize _PARAMS((StoreEntry **, StoreEntry **));
#endif
static struct _store_client *storeClientListSearch _PARAMS((const MemObject *, void *));
static int storeCopy _PARAMS((const StoreEntry *, off_t, size_t, char *, size_t *));
static int storeEntryLocked _PARAMS((const StoreEntry *));
static int storeEntryValidLength _PARAMS((const StoreEntry *));
static void storeGetMemSpace _PARAMS((int));
static int storeHashDelete _PARAMS((StoreEntry *));
static VCB storeSwapInValidateComplete;
static mem_hdr *new_MemObjectData _PARAMS((void));
static MemObject *new_MemObject _PARAMS((const char *));
static StoreEntry *new_StoreEntry _PARAMS((int, const char *));
static StoreEntry *storeAddDiskRestore _PARAMS((const char *,
	int,
	int,
	time_t,
	time_t,
	time_t,
	time_t,
	u_num32,
	u_num32,
	int));
static unsigned int storeGetBucketNum _PARAMS((void));
static void destroy_MemObject _PARAMS((MemObject *));
static void destroy_MemObjectData _PARAMS((MemObject *));
static void destroy_StoreEntry _PARAMS((StoreEntry *));
static void storePurgeMem _PARAMS((StoreEntry *));
static void storeStartRebuildFromDisk _PARAMS((void));
static void storeSwapOutStart _PARAMS((StoreEntry * e));
static DWCB storeSwapOutHandle;
static void storeSetPrivateKey _PARAMS((StoreEntry *));
static EVH storeDoRebuildFromDisk;
static EVH storeCleanup;
static VCB storeCleanupComplete;
static void storeValidate _PARAMS((StoreEntry *, VCB *, void *));
static AIOCB storeValidateComplete;
static void storeRebuiltFromDisk _PARAMS((struct storeRebuildState * data));
static unsigned int getKeyCounter _PARAMS((void));
static void storePutUnusedFileno _PARAMS((int fileno));
static int storeGetUnusedFileno _PARAMS((void));

static void storeCheckSwapOut(StoreEntry * e);
static void storeSwapoutFileOpened(void *data, int fd);
static int storeCheckCachable(StoreEntry * e);
static int storeKeepInMemory(const StoreEntry *);
static SIH storeClientCopyFileOpened;
static DRCB storeClientCopyHandleRead;
static FOCB storeSwapInFileOpened;
static void storeClientCopyFileRead(struct _store_client *sc);
static void storeInMemAdd(StoreEntry * e);
static void storeInMemDelete(StoreEntry * e);
static void storeSetMemStatus(StoreEntry * e, int);

/* Now, this table is inaccessible to outsider. They have to use a method
 * to access a value in internal storage data structure. */
static hash_table *store_table = NULL;
static struct _mem_entry *inmem_head = NULL;
static struct _mem_entry *inmem_tail = NULL;

static int store_pages_max = 0;
static int store_pages_high = 0;
static int store_pages_low = 0;

/* current file name, swap file, use number as a filename */
static int store_swap_high = 0;
static int store_swap_low = 0;
static int storelog_fd = -1;

/* key temp buffer */
static char key_temp_buffer[MAX_URL + 100];

/* expiration parameters and stats */
static int store_buckets;
static int store_maintain_rate;
static int store_maintain_buckets;
static int scan_revolutions;
static struct _bucketOrder *MaintBucketsOrder = NULL;

static MemObject *
new_MemObject(const char *log_url)
{
    MemObject *mem = get_free_mem_obj();
    mem->reply = xcalloc(1, sizeof(struct _http_reply));
    mem->reply->date = -2;
    mem->reply->expires = -2;
    mem->reply->last_modified = -2;
    mem->log_url = xstrdup(log_url);
    mem->swapout.fd = -1;
    meta_data.mem_obj_count++;
    meta_data.misc += sizeof(struct _http_reply);
    meta_data.url_strings += strlen(log_url);
    debug(20, 3) ("new_MemObject: returning %p\n", mem);
    return mem;
}

static StoreEntry *
new_StoreEntry(int mem_obj_flag, const char *log_url)
{
    StoreEntry *e = NULL;

    e = xcalloc(1, sizeof(StoreEntry));
    meta_data.store_entries++;
    if (mem_obj_flag)
	e->mem_obj = new_MemObject(log_url);
    debug(20, 3) ("new_StoreEntry: returning %p\n", e);
    return e;
}

static void
destroy_MemObject(MemObject * mem)
{
    debug(20, 3) ("destroy_MemObject: destroying %p\n", mem);
    assert(mem->swapout.fd == -1);
    destroy_MemObjectData(mem);
    meta_data.url_strings -= strlen(mem->log_url);
    safe_free(mem->clients);
    safe_free(mem->reply);
    safe_free(mem->log_url);
    requestUnlink(mem->request);
    mem->request = NULL;
    put_free_mem_obj(mem);
    meta_data.mem_obj_count--;
    meta_data.misc -= sizeof(struct _http_reply);
}

static void
destroy_StoreEntry(StoreEntry * e)
{
    debug(20, 3) ("destroy_StoreEntry: destroying %p\n", e);
    assert(e != NULL);
    if (e->mem_obj)
	destroy_MemObject(e->mem_obj);
    if (e->url) {
	meta_data.url_strings -= strlen(e->url);
	safe_free(e->url);
    } else {
	debug(20, 3) ("destroy_StoreEntry: WARNING: Entry without URL string!\n");
    }
    if (BIT_TEST(e->flag, KEY_URL))
	e->key = NULL;
    else
	safe_free(e->key);
    xfree(e);
    meta_data.store_entries--;
}

static mem_hdr *
new_MemObjectData(void)
{
    debug(20, 3) ("new_MemObjectData: calling memInit()\n");
    meta_data.mem_data_count++;
    return memInit();
}

static void
destroy_MemObjectData(MemObject * mem)
{
    debug(20, 3) ("destroy_MemObjectData: destroying %p, %d bytes\n",
	mem->data, mem->inmem_hi);
    store_mem_size -= ENTRY_INMEM_SIZE(mem);
    if (mem->data) {
	memFree(mem->data);
	mem->data = NULL;
	meta_data.mem_data_count--;
    }
    mem->inmem_hi = 0;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

static void
storeCreateHashTable(HASHCMP * cmp_func)
{
    store_table = hash_create(cmp_func, store_buckets, hash4);
}

static int
storeHashInsert(StoreEntry * e)
{
    debug(20, 3) ("storeHashInsert: Inserting Entry %p key '%s'\n",
	e, e->key);
    return hash_join(store_table, (hash_link *) e);
}

static int
storeHashDelete(StoreEntry * e)
{
    return hash_remove_link(store_table, (hash_link *) e);
}

/* -------------------------------------------------------------------------- */

static void
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
	debug(20, 1) ("storeLog: NULL log_url for %s\n", e->url);
	storeMemObjectDump(mem);
	mem->log_url = xstrdup(e->url);
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
	RequestMethodStr[e->method],
	mem->log_url);
    file_write(storelog_fd,
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
    debug(20, 3) ("storePurgeMem: Freeing memory-copy of %s\n", e->key);
    storeSetMemStatus(e, NOT_IN_MEMORY);
    destroy_MemObject(e->mem_obj);
    e->mem_obj = NULL;
}

void
storeLockObject(StoreEntry * e)
{
    e->lock_count++;
    debug(20, 3) ("storeLockObject: key '%s' count=%d\n",
	e->key, (int) e->lock_count);
    e->lastref = squid_curtime;
}

void
storeReleaseRequest(StoreEntry * e)
{
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	return;
    if (!storeEntryLocked(e))
	fatal_dump("storeReleaseRequest: unlocked entry");
    debug(20, 3) ("storeReleaseRequest: '%s'\n",
	e->key ? e->key : e->url);
    BIT_SET(e->flag, RELEASE_REQUEST);
    storeSetPrivateKey(e);
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */
int
storeUnlockObject(StoreEntry * e)
{
    e->lock_count--;
    debug(20, 3) ("storeUnlockObject: key '%s' count=%d\n",
	e->key, e->lock_count);
    if (e->lock_count)
	return (int) e->lock_count;
    if (e->store_status == STORE_PENDING) {
	assert(!BIT_TEST(e->flag, ENTRY_DISPATCHED));
	BIT_SET(e->flag, RELEASE_REQUEST);
    }
    assert(storePendingNClients(e) == 0);
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
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
storeGet(const char *url)
{
    debug(20, 3) ("storeGet: looking up %s\n", url);
    return (StoreEntry *) hash_lookup(store_table, url);
}

static unsigned int
getKeyCounter(void)
{
    static unsigned int key_counter = 0;
    if (++key_counter == (1 << 24))
	key_counter = 1;
    return key_counter;
}

unsigned int
storeReqnum(StoreEntry * entry, method_t method)
{
    unsigned int k;
    if (BIT_TEST(entry->flag, KEY_PRIVATE))
	k = atoi(entry->key);
    else
	k = getKeyCounter();
    if (method == METHOD_GET)
	return k;
    return (method << 24) | k;
}

const char *
storeGeneratePrivateKey(const char *url, method_t method, int num)
{
    if (num == 0)
	num = getKeyCounter();
    else if (num & 0xFF000000) {
	method = (method_t) (num >> 24);
	num &= 0x00FFFFFF;
    }
    debug(20, 3) ("storeGeneratePrivateKey: '%s'\n", url);
    key_temp_buffer[0] = '\0';
    snprintf(key_temp_buffer, MAX_URL + 100, "%d/%s/%s",
	num,
	RequestMethodStr[method],
	url);
    return key_temp_buffer;
}

const char *
storeGeneratePublicKey(const char *url, method_t method)
{
    debug(20, 3) ("storeGeneratePublicKey: type=%d %s\n", method, url);
    switch (method) {
    case METHOD_GET:
	return url;
	/* NOTREACHED */
	break;
    case METHOD_POST:
    case METHOD_PUT:
    case METHOD_HEAD:
    case METHOD_CONNECT:
    case METHOD_TRACE:
	snprintf(key_temp_buffer, MAX_URL + 100, "/%s/%s", RequestMethodStr[method], url);
	return key_temp_buffer;
	/* NOTREACHED */
	break;
    default:
	fatal_dump("storeGeneratePublicKey: Unsupported request method");
	break;
    }
    return NULL;
}

static void
storeSetPrivateKey(StoreEntry * e)
{
    const char *newkey = NULL;
    if (e->key && BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already private */
    newkey = storeGeneratePrivateKey(e->url, e->method, 0);
    assert(hash_lookup(store_table, newkey) == NULL);
    if (e->key)
	storeHashDelete(e);
    if (e->key && !BIT_TEST(e->flag, KEY_URL))
	safe_free(e->key);
    e->key = xstrdup(newkey);
    storeHashInsert(e);
    BIT_RESET(e->flag, KEY_URL);
    BIT_SET(e->flag, KEY_CHANGE);
    BIT_SET(e->flag, KEY_PRIVATE);
}

void
storeSetPublicKey(StoreEntry * e)
{
    StoreEntry *e2 = NULL;
    hash_link *table_entry = NULL;
    const char *newkey = NULL;
    int loop_detect = 0;
    if (e->key && !BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already public */
    newkey = storeGeneratePublicKey(e->url, e->method);
    while ((table_entry = hash_lookup(store_table, newkey))) {
	debug(20, 3) ("storeSetPublicKey: Making old '%s' private.\n", newkey);
	e2 = (StoreEntry *) table_entry;
	storeSetPrivateKey(e2);
	storeRelease(e2);
	assert(++loop_detect < 10);
	newkey = storeGeneratePublicKey(e->url, e->method);
    }
    if (e->key)
	storeHashDelete(e);
    if (e->key && !BIT_TEST(e->flag, KEY_URL))
	safe_free(e->key);
    if (e->method == METHOD_GET) {
	e->key = e->url;
	BIT_SET(e->flag, KEY_URL);
	BIT_RESET(e->flag, KEY_CHANGE);
    } else {
	e->key = xstrdup(newkey);
	BIT_RESET(e->flag, KEY_URL);
	BIT_SET(e->flag, KEY_CHANGE);
    }
    BIT_RESET(e->flag, KEY_PRIVATE);
    storeHashInsert(e);
}

StoreEntry *
storeCreateEntry(const char *url, const char *log_url, int flags, method_t method)
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    debug(20, 3) ("storeCreateEntry: '%s' icp flags=%x\n", url, flags);

    e = new_StoreEntry(WITH_MEMOBJ, log_url);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    e->url = xstrdup(url);
    meta_data.url_strings += strlen(url);
    e->method = method;
    if (neighbors_do_private_keys || !BIT_TEST(flags, REQ_HIERARCHICAL))
	storeSetPrivateKey(e);
    else
	storeSetPublicKey(e);
    if (BIT_TEST(flags, REQ_CACHABLE)) {
	BIT_SET(e->flag, ENTRY_CACHABLE);
	BIT_RESET(e->flag, RELEASE_REQUEST);
    } else {
	BIT_RESET(e->flag, ENTRY_CACHABLE);
	storeReleaseRequest(e);
    }
    if (BIT_TEST(flags, REQ_HIERARCHICAL))
	BIT_SET(e->flag, HIERARCHICAL);
    else
	BIT_RESET(e->flag, HIERARCHICAL);
    e->store_status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_NONE;
    e->swap_file_number = -1;
    mem->data = new_MemObjectData();
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = 0;		/* set in storeTimestampsSet() */
    e->ping_status = PING_NONE;
    BIT_SET(e->flag, ENTRY_VALIDATED);

    /* allocate client list */
    mem->nclients = MIN_CLIENT;
    mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
    /* storeLog(STORE_LOG_CREATE, e); */
    return e;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
static StoreEntry *
storeAddDiskRestore(const char *url,
    int file_number,
    int size,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_num32 refcount,
    u_num32 flags,
    int clean)
{
    StoreEntry *e = NULL;
    debug(20, 5) ("StoreAddDiskRestore: %s, fileno=%08X\n", url, file_number);
    /* if you call this you'd better be sure file_number is not 
     * already in use! */
    meta_data.url_strings += strlen(url);
    e = new_StoreEntry(WITHOUT_MEMOBJ, NULL);
    e->url = xstrdup(url);
    e->method = METHOD_GET;
    storeSetPublicKey(e);
    assert(e->key);
    e->store_status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAPOUT_DONE;
    e->swap_file_number = file_number;
    e->object_len = size;
    e->lock_count = 0;
    e->refcount = 0;
    e->lastref = lastref;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->refcount = refcount;
    e->flag = flags;
    BIT_SET(e->flag, ENTRY_CACHABLE);
    BIT_RESET(e->flag, RELEASE_REQUEST);
    BIT_RESET(e->flag, KEY_PRIVATE);
    e->ping_status = PING_NONE;
    if (clean) {
	BIT_SET(e->flag, ENTRY_VALIDATED);
	/* Only set the file bit if we know its a valid entry */
	/* otherwise, set it in the validation procedure */
	storeDirMapBitSet(file_number);
    } else {
	BIT_RESET(e->flag, ENTRY_VALIDATED);
    }
    return e;
}

int
storeUnregister(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    struct _store_client *sc;
    if (mem == NULL)
	return 0;
    debug(20, 3) ("storeUnregister: called for '%s'\n", e->key);
    sc = storeClientListSearch(mem, data);
    if (sc == NULL)
	return 0;
    if (e->store_status == STORE_OK && e->swap_status != SWAPOUT_DONE)
    	storeCheckSwapOut(e);
    sc->seen_offset = 0;
    sc->copy_offset = 0;
    if (sc->swapin_fd > -1)
	file_close(sc->swapin_fd);
    sc->swapin_fd = -1;
    sc->callback = NULL;
    sc->callback_data = NULL;
    debug(20, 9) ("storeUnregister: returning 1\n");
    return 1;
}

off_t
storeLowestMemReaderOffset(const StoreEntry * entry)
{
    const MemObject *mem = entry->mem_obj;
    off_t lowest = mem->inmem_hi;
    int i;
    struct _store_client *sc;
    for (i = 0; i < mem->nclients; i++) {
	sc = &mem->clients[i];
	if (sc->callback_data == NULL)	/* open slot */
	    continue;
	if (sc->swapin_fd > -1)	/* reading from disk */
	    continue;
	if (sc->copy_offset < lowest)
	    lowest = sc->copy_offset;
    }
    return lowest;
}

/* Call handlers waiting for  data to be appended to E. */
void
InvokeHandlers(const StoreEntry * e)
{
    int i;
    MemObject *mem = e->mem_obj;
    STCB *callback = NULL;
    struct _store_client *sc;
    ssize_t size;
    assert(mem->clients != NULL || mem->nclients == 0);
    debug(20, 3) ("InvokeHandlers: %s\n", e->key);
    /* walk the entire list looking for valid callbacks */
    for (i = 0; i < mem->nclients; i++) {
	debug(20, 3) ("InvokeHandlers: checking client #%d\n", i);
	sc = &mem->clients[i];
	if (sc->callback_data == NULL)
	    continue;
	if ((callback = sc->callback) == NULL)
	    continue;
	sc->callback = NULL;
	/* Don't NULL the callback_data, its used to identify the client */
	size = memCopy(mem->data,
	    sc->copy_offset,
	    sc->copy_buf,
	    sc->copy_size);
	debug(20, 3) ("InvokeHandlers: calling handler: %p\n", callback);
	callback(sc->callback_data, sc->copy_buf, size);
    }
}

/* Mark object as expired */
void
storeExpireNow(StoreEntry * e)
{
    debug(20, 3) ("storeExpireNow: '%s'\n", e->key);
    e->expires = squid_curtime;
}

static void
storeSwapoutFileOpened(void *data, int fd)
{
    swapout_ctrl_t *ctrlp = data;
    int oldswapstatus = ctrlp->oldswapstatus;
    char *swapfilename = ctrlp->swapfilename;
    StoreEntry *e = ctrlp->e;
    MemObject *mem;
    xfree(ctrlp);
    assert(e->swap_status == SWAPOUT_OPENING);
    if (fd < 0) {
	debug(20, 0) ("storeSwapoutFileOpened: Unable to open swapfile: %s\n",
	    swapfilename);
	storeDirMapBitReset(e->swap_file_number);
	e->swap_file_number = -1;
	e->swap_status = oldswapstatus;
	xfree(swapfilename);
	return;
    }
    mem = e->mem_obj;
    mem->swapout.fd = (short) fd;
    e->swap_status = SWAPOUT_WRITING;
    debug(20, 5) ("storeSwapoutFileOpened: Begin SwapOut '%s' to FD %d FILE %s.\n",
	e->url, fd, swapfilename);
    xfree(swapfilename);
    debug(20, 5) ("swap_file_number=%08X\n", e->swap_file_number);
    /*mem->swap_offset = 0; */
    mem->e_swap_buf = get_free_8k_page();
    mem->e_swap_buf_len = 0;
    storeCheckSwapOut(e);
}

/* start swapping object to disk */
static void
storeSwapOutStart(StoreEntry * e)
{
    swapout_ctrl_t *ctrlp;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN);
    storeLockObject(e);
    if ((e->swap_file_number = storeGetUnusedFileno()) < 0)
	e->swap_file_number = storeDirMapAllocate();
    storeSwapFullPath(e->swap_file_number, swapfilename);
    ctrlp = xmalloc(sizeof(swapout_ctrl_t));
    ctrlp->swapfilename = xstrdup(swapfilename);
    ctrlp->e = e;
    ctrlp->oldswapstatus = e->swap_status;
    e->swap_status = SWAPOUT_OPENING;
    file_open(swapfilename,
	O_WRONLY | O_CREAT | O_TRUNC,
	storeSwapoutFileOpened,
	ctrlp);
}

static void
storeSwapOutHandle(int fd, int flag, size_t len, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    debug(20, 3) ("storeSwapOutHandle: '%s', len=%d\n", e->key, (int) len);
    assert(mem != NULL);
    if (flag < 0) {
	debug(20, 1) ("storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = SWAPOUT_NONE;
	put_free_8k_page(mem->e_swap_buf);
	file_close(mem->swapout.fd);
	mem->swapout.fd = -1;
	if (e->swap_file_number != -1) {
	    storePutUnusedFileno(e->swap_file_number);
	    e->swap_file_number = -1;
	}
	storeRelease(e);
	if (flag == DISK_NO_SPACE_LEFT) {
	    /* reduce the swap_size limit to the current size. */
	    Config.Swap.maxSize = store_swap_size;
	    storeConfigure();
	}
	return;
    }
    storeDirUpdateSwapSize(e->swap_file_number, len, 1);
    mem->swapout.done_offset += len;
    if (e->store_status == STORE_PENDING || mem->swapout.done_offset < e->object_len) {
	storeCheckSwapOut(e);
	return;
    }
    assert(storeCheckCachable(e));
    /* swapping complete */
    e->swap_status = SWAPOUT_DONE;
    file_close(mem->swapout.fd);
    mem->swapout.fd = -1;
    storeLog(STORE_LOG_SWAPOUT, e);
    debug(20, 5) ("storeSwapOutHandle: SwapOut complete: '%s' to %s.\n",
	e->url, storeSwapFullPath(e->swap_file_number, NULL));
    put_free_8k_page(mem->e_swap_buf);
    storeDirSwapLog(e);
    HTTPCacheInfo->proto_newobject(HTTPCacheInfo,
	mem->request->protocol,
	e->object_len,
	FALSE);
    storeUnlockObject(e);
}

static void
storeCheckSwapOut(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    int x;
    off_t lowest_offset;
    off_t new_mem_lo;
    size_t swapout_size;
    assert(mem != NULL);
    /* should we swap something out to disk? */
    debug(20, 3) ("storeCheckSwapOut: %s\n", e->url);
    debug(20, 3) ("storeCheckSwapOut: store_status = %s\n",
	storeStatusStr[e->store_status]);
    if (e->store_status == STORE_ABORTED)
	return;

    debug(20, 3) ("storeCheckSwapOut: mem->inmem_lo = %d\n",
	(int) mem->inmem_lo);
    debug(20, 3) ("storeCheckSwapOut: mem->inmem_hi = %d\n",
	(int) mem->inmem_hi);
    assert(mem->inmem_hi >= mem->swapout.queue_offset);
    swapout_size = (size_t) (mem->inmem_hi - mem->swapout.queue_offset);
    lowest_offset = storeLowestMemReaderOffset(e);
    debug(20, 3) ("storeCheckSwapOut: lowest_offset = %d\n",
	(int) lowest_offset);
    assert(lowest_offset >= mem->inmem_lo);

    new_mem_lo = lowest_offset;
    if (!BIT_TEST(e->flag, ENTRY_CACHABLE)) {
	memFreeDataUpto(mem->data, new_mem_lo);
	mem->inmem_lo = new_mem_lo;
	return;
    }
    if (mem->swapout.queue_offset < new_mem_lo)
	new_mem_lo = mem->swapout.queue_offset;
    memFreeDataUpto(mem->data, new_mem_lo);
    mem->inmem_lo = new_mem_lo;

    swapout_size = (size_t) (mem->inmem_hi - mem->swapout.queue_offset);
    debug(20, 3) ("storeCheckSwapOut: swapout_size = %d\n",
	(int) swapout_size);
    if (swapout_size == 0)
	return;
    if (e->store_status == STORE_PENDING && swapout_size < VM_WINDOW_SZ)
	return;			/* wait for a full block */
    /* Ok, we have stuff to swap out.  Is there a swapout.fd open? */
    if (e->swap_status == SWAPOUT_NONE) {
	assert(mem->swapout.fd == -1);
	if (storeCheckCachable(e))
		storeSwapOutStart(e);
	/* else ENTRY_CACHABLE will be cleared and we'll never get
	  here again */
	return;
    }
    if (e->swap_status == SWAPOUT_OPENING)
	return;
    assert(mem->swapout.fd > -1);
    if (swapout_size > SWAP_BUF)
	swapout_size = SWAP_BUF;
    debug(20, 3) ("storeCheckSwapOut: swapout.queue_offset = %d\n", (int) mem->swapout.queue_offset);
    x = storeCopy(e,
	mem->swapout.queue_offset,
	swapout_size,
	mem->e_swap_buf,
	&mem->e_swap_buf_len);
    if (x < 0) {
	debug(20, 1) ("storeCopy returned %d for '%s'\n", x, e->key);
	e->swap_file_number = -1;
	file_close(mem->swapout.fd);
	mem->swapout.fd = -1;
	storeDirMapBitReset(e->swap_file_number);
	safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
	e->swap_file_number = -1;
	e->swap_status = SWAPOUT_NONE;
	return;
    }
    debug(20, 3) ("storeCheckSwapOut: e_swap_buf_len = %d\n", (int) mem->e_swap_buf_len);
    assert(mem->e_swap_buf_len > 0);
    debug(20, 3) ("storeCheckSwapOut: swapping out %d bytes from %d\n",
	mem->e_swap_buf_len, mem->swapout.queue_offset);
    mem->swapout.queue_offset += mem->e_swap_buf_len;
    x = file_write(mem->swapout.fd,
	mem->e_swap_buf,
	mem->e_swap_buf_len,
	storeSwapOutHandle,
	e,
	NULL);
    assert(x == DISK_OK);
}

/* Append incoming data from a primary server to an entry. */
void
storeAppend(StoreEntry * e, const char *buf, int len)
{
    MemObject *mem = e->mem_obj;
    assert(mem != NULL);
    assert(len >= 0);
    if (len) {
	debug(20, 5) ("storeAppend: appending %d bytes for '%s'\n", len, e->key);
	storeGetMemSpace(len);
#if OLD_CODE
	if (sm_stats.n_pages_in_use > store_pages_low) {
	    if (mem->inmem_hi > Config.Store.maxObjectSize)
		storeStartDeleteBehind(e);
	}
#endif
	store_mem_size += len;
	memAppend(mem->data, buf, len);
	mem->inmem_hi += len;
    }
    if (e->store_status != STORE_ABORTED && !BIT_TEST(e->flag, DELAY_SENDING))
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

/* start swapping in */
void
storeSwapInStart(StoreEntry * e, SIH * callback, void *callback_data)
{
    swapin_ctrl_t *ctrlp;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED)) {
	if (storeDirMapBitTest(e->swap_file_number)) {
	    /* someone took our file while we weren't looking */
	    callback(-1, callback_data);
	    return;
	}
    }
    assert(e->swap_status == SWAPOUT_WRITING || e->swap_status == SWAPOUT_DONE);
    assert(e->swap_file_number >= 0);
    assert(e->mem_obj != NULL);
    ctrlp = xmalloc(sizeof(swapin_ctrl_t));
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
    if (BIT_TEST(e->flag, ENTRY_VALIDATED))
	storeSwapInValidateComplete(ctrlp);
    else
	storeValidate(e, storeSwapInValidateComplete, ctrlp);
}


static void
storeSwapInValidateComplete(void *data)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e;
    e = ctrlp->e;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED)) {
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (-1, ctrlp->callback_data);
	xfree(ctrlp);
	return;
    }
    ctrlp->path = xstrdup(storeSwapFullPath(e->swap_file_number, NULL));
    file_open(ctrlp->path, O_RDONLY, storeSwapInFileOpened, ctrlp);
}

static void
storeSwapInFileOpened(void *data, int fd)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e = ctrlp->e;
    assert(e->mem_obj != NULL);
    assert(e->mem_status == NOT_IN_MEMORY);
    assert(e->swap_status == SWAPOUT_DONE);
    if (fd < 0) {
	debug(20, 0) ("storeSwapInStartComplete: Failed for '%s'\n", e->url);
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (-1, ctrlp->callback_data);
	xfree(ctrlp->path);
	xfree(ctrlp);
	return;
    }
    debug(20, 5) ("storeSwapInStart: initialized swap file '%s' for '%s'\n",
	ctrlp->path, e->url);
    (ctrlp->callback) (fd, ctrlp->callback_data);
    xfree(ctrlp->path);
    xfree(ctrlp);
}

/* recreate meta data from disk image in swap directory */
/* Add one swap file at a time from disk storage */
static void
storeDoRebuildFromDisk(void *data)
{
    struct storeRebuildState *RB = data;
    LOCAL_ARRAY(char, swapfile, MAXPATHLEN);
    LOCAL_ARRAY(char, url, MAX_URL);
    StoreEntry *e = NULL;
    time_t expires;
    time_t timestamp;
    time_t lastref;
    time_t lastmod;
    int scan1;
    int scan2;
    int scan3;
    int scan4;
    int scan5;
    int scan6;
    int scan7;
    off_t size;
    int sfileno = 0;
    int count;
    int x;
    struct _rebuild_dir *d;
    struct _rebuild_dir **D;
    int used;			/* is swapfile already in use? */
    int newer;			/* is the log entry newer than current entry? */

    /* load a number of objects per invocation */
    if ((d = RB->rebuild_dir) == NULL) {
	storeRebuiltFromDisk(RB);
	return;
    }
    for (count = 0; count < d->speed; count++) {
	if (fgets(RB->line_in, RB->line_in_sz, d->log) == NULL) {
	    debug(20, 1) ("Done reading Cache Dir #%d swap log\n", d->dirn);
	    fclose(d->log);
	    d->log = NULL;
	    storeDirCloseTmpSwapLog(d->dirn);
	    RB->rebuild_dir = d->next;
	    safe_free(d);
	    eventAdd("storeRebuild", storeDoRebuildFromDisk, RB, 0);
	    return;
	}
	if ((++RB->linecount & 0x3FFF) == 0)
	    debug(20, 1) ("  %7d Lines read so far.\n", RB->linecount);
	debug(20, 9) ("line_in: %s", RB->line_in);
	if (RB->line_in[0] == '\0')
	    continue;
	if (RB->line_in[0] == '\n')
	    continue;
	if (RB->line_in[0] == '#')
	    continue;
	url[0] = '\0';
	sfileno = 0;
	scan1 = 0;
	scan2 = 0;
	scan3 = 0;
	scan4 = 0;
	scan5 = 0;
	scan6 = 0;
	scan7 = 0;
	x = sscanf(RB->line_in, "%x %x %x %x %x %d %d %x %s",
	    &sfileno,		/* swap_file_number */
	    &scan1,		/* timestamp */
	    &scan2,		/* lastref */
	    &scan3,		/* expires */
	    &scan4,		/* last modified */
	    &scan5,		/* size */
	    &scan6,		/* refcount */
	    &scan7,		/* flags */
	    url);		/* url */
	if (x < 1) {
	    RB->invalid++;
	    continue;
	}
	if (strncmp(url, "http://internal.squid", 21) == 0)
	    continue;
	storeSwapFullPath(sfileno, swapfile);
	if (x != 9) {
	    RB->invalid++;
	    continue;
	}
	if (sfileno < 0) {
	    RB->invalid++;
	    continue;
	}
	if (BIT_TEST(scan7, KEY_PRIVATE)) {
	    RB->badflags++;
	    continue;
	}
	sfileno = storeDirProperFileno(d->dirn, sfileno);
	timestamp = (time_t) scan1;
	lastref = (time_t) scan2;
	expires = (time_t) scan3;
	lastmod = (time_t) scan4;
	size = (off_t) scan5;

	e = storeGet(url);
	used = storeDirMapBitTest(sfileno);
	/* If this URL already exists in the cache, does the swap log
	 * appear to have a newer entry?  Compare 'timestamp' from the
	 * swap log to e->lastref.  Note, we can't compare e->timestamp
	 * because it is the Date: header from the HTTP reply and
	 * doesn't really tell us when the object was added to the
	 * cache. */
	newer = e ? (timestamp > e->lastref ? 1 : 0) : 0;
	if (used && !newer) {
	    /* log entry is old, ignore it */
	    RB->clashcount++;
	    continue;
	} else if (used && e && e->swap_file_number == sfileno) {
	    /* swapfile taken, same URL, newer, update meta */
	    e->lastref = timestamp;
	    e->timestamp = timestamp;
	    e->expires = expires;
	    e->lastmod = lastmod;
	    e->flag |= (u_num32) scan6;
	    e->refcount += (u_num32) scan7;
	    continue;
	} else if (used) {
	    /* swapfile in use, not by this URL, log entry is newer */
	    /* This is sorta bad: the log entry should NOT be newer at this
	     * point.  If the log is dirty, the filesize check should have
	     * caught this.  If the log is clean, there should never be a
	     * newer entry. */
	    debug(20, 1) ("WARNING: newer swaplog entry for fileno %08X\n",
		sfileno);
	    /* I'm tempted to remove the swapfile here just to be safe,
	     * but there is a bad race condition in the NOVM version if
	     * the swapfile has recently been opened for writing, but
	     * not yet opened for reading.  Because we can't map
	     * swapfiles back to StoreEntrys, we don't know the state
	     * of the entry using that file.  */
	    /* We'll assume the existing entry is valid, probably because
	     * were in a slow rebuild and the the swap file number got taken
	     * and the validation procedure hasn't run. */
	    assert(RB->need_to_validate);
	    RB->clashcount++;
	    continue;
	} else if (e) {
	    /* URL already exists, this swapfile not being used */
	    /* junk old, load new */
	    storeRelease(e);	/* release old entry */
	    RB->dupcount++;
	} else {
	    /* URL doesnt exist, swapfile not in use */
	    /* load new */
	    (void) 0;
	}
	/* update store_swap_size */
	storeDirUpdateSwapSize(sfileno, size, 1);
	RB->objcount++;
	e = storeAddDiskRestore(url,
	    sfileno,
	    (int) size,
	    expires,
	    timestamp,
	    lastref,
	    lastmod,
	    (u_num32) scan6,	/* refcount */
	    (u_num32) scan7,	/* flags */
	    d->clean);
	storeDirSwapLog(e);
	HTTPCacheInfo->proto_newobject(HTTPCacheInfo,
	    urlParseProtocol(url),
	    (int) size,
	    TRUE);
    }
    RB->rebuild_dir = d->next;
    for (D = &RB->rebuild_dir; *D; D = &(*D)->next);
    *D = d;
    d->next = NULL;
    eventAdd("storeRebuild", storeDoRebuildFromDisk, RB, 0);
}

static void
storeCleanup(void *data)
{
    static storeCleanList *list = NULL;
    storeCleanList *curr;
    static int bucketnum = -1;
    static int validnum = 0;
    StoreEntry *e;
    hash_link *link_ptr = NULL;
    if (list == NULL) {
	if (++bucketnum >= store_buckets) {
	    debug(20, 1) ("  Completed Validation Procedure\n");
	    debug(20, 1) ("  Validated %d Entries\n", validnum);
	    store_rebuilding = 0;
	    return;
	}
	link_ptr = hash_get_bucket(store_table, bucketnum);
	for (; link_ptr; link_ptr = link_ptr->next) {
	    e = (StoreEntry *) link_ptr;
	    if (BIT_TEST(e->flag, ENTRY_VALIDATED))
		continue;
	    if (BIT_TEST(e->flag, RELEASE_REQUEST))
		continue;
	    curr = xcalloc(1, sizeof(storeCleanList));
	    curr->key = xstrdup(e->key);
	    curr->next = list;
	    list = curr;
	}
    }
    if (list == NULL) {
	eventAdd("storeCleanup", storeCleanup, NULL, 0);
	return;
    }
    curr = list;
    list = list->next;
    e = (StoreEntry *) hash_lookup(store_table, curr->key);
    if (e && !BIT_TEST(e->flag, ENTRY_VALIDATED)) {
	storeLockObject(e);
	storeValidate(e, storeCleanupComplete, e);
	if ((++validnum & 0xFFF) == 0)
	    debug(20, 1) ("  %7d Entries Validated so far.\n", validnum);
	assert(validnum <= meta_data.store_entries);
    }
    xfree(curr->key);
    xfree(curr);
    eventAdd("storeCleanup", storeCleanup, NULL, 0);
}

static void
storeCleanupComplete(void *data)
{
    StoreEntry *e = data;
    storeUnlockObject(e);
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED))
	storeRelease(e);
}

static void
storeValidate(StoreEntry * e, VCB callback, void *callback_data)
{
    valid_ctrl_t *ctrlp;
    char *path;
    struct stat *sb;
#if !USE_ASYNC_IO
    int x;
#endif
    assert(!BIT_TEST(e->flag, ENTRY_VALIDATED));
    if (e->swap_file_number < 0) {
	BIT_RESET(e->flag, ENTRY_VALIDATED);
	callback(callback_data);
	return;
    }
    path = storeSwapFullPath(e->swap_file_number, NULL);
    sb = xmalloc(sizeof(struct stat));
    ctrlp = xmalloc(sizeof(valid_ctrl_t));
    ctrlp->sb = sb;
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
#if USE_ASYNC_IO
    aioStat(path, sb, storeValidateComplete, ctrlp);
#else
    /* When evaluating the actual arguments in a function call, the order
     * in which the arguments and the function expression are evaluated is
     * not specified; */
    x = stat(path, sb);
    storeValidateComplete(ctrlp, x, errno);
#endif
    return;
}

static void
storeValidateComplete(void *data, int retcode, int errcode)
{
    valid_ctrl_t *ctrlp = data;
    struct stat *sb = ctrlp->sb;
    StoreEntry *e = ctrlp->e;
    char *path;
    if (retcode < 0 && errcode == EWOULDBLOCK) {
	path = storeSwapFullPath(e->swap_file_number, NULL);
	retcode = stat(path, sb);
    }
    if (retcode < 0 || sb->st_size == 0 || sb->st_size != e->object_len) {
	BIT_RESET(e->flag, ENTRY_VALIDATED);
    } else {
	BIT_SET(e->flag, ENTRY_VALIDATED);
	storeDirMapBitSet(e->swap_file_number);
    }
    errno = errcode;
    ctrlp->callback(ctrlp->callback_data);
    xfree(sb);
    xfree(ctrlp);
}

/* meta data recreated from disk image in swap directory */
static void
storeRebuiltFromDisk(struct storeRebuildState *data)
{
    time_t r;
    time_t stop;
    stop = squid_curtime;
    r = stop - data->start;
    debug(20, 1) ("Finished rebuilding storage from disk image.\n");
    debug(20, 1) ("  %7d Lines read from previous logfile.\n", data->linecount);
    debug(20, 1) ("  %7d Invalid lines.\n", data->invalid);
    debug(20, 1) ("  %7d With invalid flags.\n", data->badflags);
    debug(20, 1) ("  %7d Objects loaded.\n", data->objcount);
    debug(20, 1) ("  %7d Objects expired.\n", data->expcount);
    debug(20, 1) ("  %7d Duplicate URLs purged.\n", data->dupcount);
    debug(20, 1) ("  %7d Swapfile clashes avoided.\n", data->clashcount);
    debug(20, 1) ("  Took %d seconds (%6.1lf objects/sec).\n",
	r > 0 ? r : 0, (double) data->objcount / (r > 0 ? r : 1));
    debug(20, 1) ("  store_swap_size = %dk\n", store_swap_size);
    if (data->need_to_validate && data->linecount) {
	debug(20, 1) ("Beginning Validation Procedure\n");
	eventAdd("storeCleanup", storeCleanup, NULL, 0);
    } else {
	store_rebuilding = 0;
    }
    safe_free(data->line_in);
    safe_free(data);
}

static void
storeStartRebuildFromDisk(void)
{
    int i;
    struct storeRebuildState *RB;
    struct _rebuild_dir *d;
    FILE *fp;
    int clean;
    RB = xcalloc(1, sizeof(struct storeRebuildState));
    RB->start = squid_curtime;
    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	fp = storeDirOpenTmpSwapLog(i, &clean);
	if (fp == NULL)
	    continue;
	d = xcalloc(1, sizeof(struct _rebuild_dir));
	d->dirn = i;
	d->log = fp;
	d->clean = clean;
	d->speed = opt_foreground_rebuild ? 1 << 30 : 50;
	d->next = RB->rebuild_dir;
	RB->rebuild_dir = d;
	if (!clean)
	    RB->need_to_validate = 1;
	debug(20, 1) ("Rebuilding storage in Cache Dir #%d (%s)\n",
	    i, clean ? "CLEAN" : "DIRTY");
    }
    RB->line_in_sz = 4096;
    RB->line_in = xcalloc(1, RB->line_in_sz);
    if (opt_foreground_rebuild) {
	storeDoRebuildFromDisk(RB);
    } else {
	eventAdd("storeRebuild", storeDoRebuildFromDisk, RB, 0);
    }
}

static int
storeCheckCachable(StoreEntry * e)
{
    if (e->method != METHOD_GET) {
	debug(20, 2) ("storeCheckCachable: NO: non-GET method\n");
    } else if (!BIT_TEST(e->flag, ENTRY_CACHABLE)) {
	debug(20, 2) ("storeCheckCachable: NO: not cachable\n");
    } else if (BIT_TEST(e->flag, RELEASE_REQUEST)) {
	debug(20, 2) ("storeCheckCachable: NO: release requested\n");
    } else if (!storeEntryValidLength(e)) {
	debug(20, 2) ("storeCheckCachable: NO: wrong content-length\n");
    } else if (BIT_TEST(e->flag, ENTRY_NEGCACHED)) {
	debug(20, 2) ("storeCheckCachable: NO: negative cached\n");
	return 0;		/* avoid release call below */
    } else if (e->mem_obj->inmem_hi > Config.Store.maxObjectSize) {
	debug(20, 2) ("storeCheckCachable: NO: too big\n");
    } else if (BIT_TEST(e->flag, KEY_PRIVATE)) {
	debug(20, 3) ("storeCheckCachable: NO: private key\n");
    } else {
	return 1;
    }
    storeReleaseRequest(e);
    BIT_RESET(e->flag, ENTRY_CACHABLE);
    return 0;
}

/* Complete transfer into the local cache.  */
void
storeComplete(StoreEntry * e)
{
    debug(20, 3) ("storeComplete: '%s'\n", e->key);
    e->object_len = e->mem_obj->inmem_hi;
    e->lastref = squid_curtime;
    e->store_status = STORE_OK;
    assert(e->mem_status == NOT_IN_MEMORY);
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
    debug(20, 6) ("storeAbort: %s\n", e->key);
    storeNegativeCache(e);
    storeReleaseRequest(e);
    e->store_status = STORE_ABORTED;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    /* No DISK swap for negative cached object */
    e->swap_status = SWAPOUT_NONE;
    e->lastref = squid_curtime;
    /* Count bytes faulted through cache but not moved to disk */
    HTTPCacheInfo->proto_touchobject(HTTPCacheInfo,
	mem->request ? mem->request->protocol : PROTO_NONE,
	mem->inmem_hi);
    /* We assign an object length here--The only other place we assign the
     * object length is in storeComplete() */
    storeLockObject(e);
    e->object_len = mem->inmem_hi;
    /* Notify the server side */
    if (cbflag && mem->abort.callback) {
	mem->abort.callback(mem->abort.data);
	mem->abort.callback = NULL;
    }
    /* Notify the client side */
    InvokeHandlers(e);
    storeUnlockObject(e);
}

/* get the first entry in the storage */
StoreEntry *
storeGetFirst(void)
{
    return ((StoreEntry *) hash_first(store_table));
}


/* get the next entry in the storage for a given search pointer */
StoreEntry *
storeGetNext(void)
{
    return ((StoreEntry *) hash_next(store_table));
}


/* Clear Memory storage to accommodate the given object len */
static void
storeGetMemSpace(int size)
{
    StoreEntry *e = NULL;
    int n_expired = 0;
    int n_purged = 0;
    int n_released = 0;
#if OLD_CODE
    int n_locked = 0;
    StoreEntry **list = NULL;
    int list_count = 0;
    int i;
    static int last_warning = 0;
#endif
    static time_t last_check = 0;
    int pages_needed;
    struct _mem_entry *m;
    struct _mem_entry *prev;
    if (squid_curtime == last_check)
	return;
    last_check = squid_curtime;
    pages_needed = (size / SM_PAGE_SIZE) + 1;
    if (sm_stats.n_pages_in_use + pages_needed < store_pages_high)
	return;
    if (store_rebuilding)
	return;
    debug(20, 2) ("storeGetMemSpace: Starting, need %d pages\n", pages_needed);
    for (m = inmem_tail; m; m = prev) {
	prev = m->prev;
	e = m->e;
	if (storeEntryLocked(e))
	    continue;
	if (storeCheckExpired(e, 0)) {
	    debug(20, 2) ("storeGetMemSpace: Expired: %s\n", e->url);
	    n_expired++;
	    storeRelease(e);
	} else {
	    storePurgeMem(e);
	    n_purged++;
	}
	if (sm_stats.n_pages_in_use + pages_needed < store_pages_low)
	    break;
    }

#if OLD_CODE
    list = xcalloc(meta_data.mem_obj_count, sizeof(ipcache_entry *));
    for (e = storeGetInMemFirst(); e; e = storeGetInMemNext()) {
	if (list_count == meta_data.mem_obj_count)
	    break;
	if (storeEntryLocked(e))
	    continue;
	if (storeCheckExpired(e, 0)) {
	    debug(20, 2) ("storeGetMemSpace: Expired: %s\n", e->url);
	    n_expired++;
	    storeRelease(e);
	} else if (storeCheckPurgeMem(e)) {
	    debug(20, 3) ("storeGetMemSpace: Adding '%s'\n", e->url);
	    *(list + list_count) = e;
	    list_count++;
	} else if (!storeEntryLocked(e)) {
	    debug(20, 3) ("storeGetMemSpace: Adding '%s'\n", e->url);
	    *(list + list_count) = e;
	    list_count++;
	} else {
	    n_locked++;
	}
    }
    debug(20, 5) ("storeGetMemSpace: Sorting LRU_list: %7d items\n", list_count);
    qsort((char *) list,
	list_count,
	sizeof(StoreEntry *),
	(QS *) compareSize);
    /* Kick LRU out until we have enough memory space */
    for (i = 0; i < list_count; i++) {
	if (sm_stats.n_pages_in_use + pages_needed < store_pages_low)
	    break;
	e = *(list + i);
	if (storeCheckPurgeMem(e)) {
	    storePurgeMem(e);
	    n_purged++;
	} else if (!storeEntryLocked(e)) {
	    /* These will be neg-cached objects */
	    n_released += storeRelease(e);
	} else {
	    fatal_dump("storeGetMemSpace: Bad Entry in LRU list");
	}
    }
    i = 3;
    if (sm_stats.n_pages_in_use > store_pages_max) {
	if (sm_stats.n_pages_in_use > last_warning * 1.10) {
	    debug(20, 0) ("WARNING: Exceeded 'cache_mem' size (%dK > %dK)\n",
		sm_stats.n_pages_in_use * 4, store_pages_max * 4);
	    last_warning = sm_stats.n_pages_in_use;
	    debug(20, 0) ("Perhaps you should increase cache_mem?\n");
	    i = 0;
	}
    }
    debug(20, i) ("storeGetMemSpace stats:\n");
    debug(20, i) ("  %6d objects locked in memory\n", n_locked);
    debug(20, i) ("  %6d LRU candidates\n", list_count);
    debug(20, i) ("  %6d were purged\n", n_purged);
    debug(20, i) ("  %6d were released\n", n_released);
    xfree(list);
#endif

    debug(20, 0) ("storeGetMemSpace stats:\n");
    debug(20, 0) ("  %6d HOT objects\n", meta_data.hot_vm);
    debug(20, 0) ("  %6d were purged\n", n_purged);
    debug(20, 0) ("  %6d were released\n", n_released);
}

#if OLD_CODE
static int
compareSize(StoreEntry ** e1, StoreEntry ** e2)
{
    if (!e1 || !e2)
	fatal_dump(NULL);
    if ((*e1)->mem_obj->inmem_hi > (*e2)->mem_obj->inmem_hi)
	return (1);
    if ((*e1)->mem_obj->inmem_hi < (*e2)->mem_obj->inmem_hi)
	return (-1);
    return (0);
}
#endif

static int
compareLastRef(StoreEntry ** e1, StoreEntry ** e2)
{
    if (!e1 || !e2)
	fatal_dump(NULL);
    if ((*e1)->lastref > (*e2)->lastref)
	return (1);
    if ((*e1)->lastref < (*e2)->lastref)
	return (-1);
    return (0);
}

static int
compareBucketOrder(struct _bucketOrder *a, struct _bucketOrder *b)
{
    return a->index - b->index;
}

/* returns the bucket number to work on,
 * pointer to next bucket after each calling
 */
static unsigned int
storeGetBucketNum(void)
{
    static unsigned int bucket = 0;
    if (bucket >= store_buckets)
	bucket = 0;
    return (bucket++);
}

#define SWAP_MAX_HELP (store_buckets/2)

/* The maximum objects to scan for maintain storage space */
#define SWAP_LRUSCAN_COUNT	1024
#define SWAP_LRU_REMOVE_COUNT	64

/* Clear Swap storage to accommodate the given object len */
int
storeGetSwapSpace(int size)
{
    static int fReduceSwap = 0;
    static int swap_help = 0;
    StoreEntry *e = NULL;
    int scanned = 0;
    int removed = 0;
    int locked = 0;
    int locked_size = 0;
    int list_count = 0;
    int scan_count = 0;
    int max_list_count = SWAP_LRUSCAN_COUNT << 1;
    int i;
    StoreEntry **LRU_list;
    hash_link *link_ptr = NULL, *next = NULL;
    int kb_size = ((size + 1023) >> 10);

    if (store_swap_size + kb_size <= store_swap_low)
	fReduceSwap = 0;
    if (!fReduceSwap && (store_swap_size + kb_size <= store_swap_high)) {
	return 0;
    }
    debug(20, 2) ("storeGetSwapSpace: Starting...\n");

    /* Set flag if swap size over high-water-mark */
    if (store_swap_size + kb_size > store_swap_high)
	fReduceSwap = 1;

    debug(20, 2) ("storeGetSwapSpace: Need %d bytes...\n", size);

    LRU_list = xcalloc(max_list_count, sizeof(StoreEntry *));
    /* remove expired objects until recover enough or no expired objects */
    for (i = 0; i < store_buckets; i++) {
	link_ptr = hash_get_bucket(store_table, storeGetBucketNum());
	if (link_ptr == NULL)
	    continue;
	/* this for loop handles one bucket of hash table */
	for (; link_ptr; link_ptr = next) {
	    if (list_count == max_list_count)
		break;
	    scanned++;
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;
	    if (!BIT_TEST(e->flag, ENTRY_VALIDATED))
		continue;
	    if (storeCheckExpired(e, 0)) {
		debug(20, 3) ("storeGetSwapSpace: Expired '%s'\n", e->url);
		storeRelease(e);
	    } else if (!storeEntryLocked(e)) {
		*(LRU_list + list_count) = e;
		list_count++;
		scan_count++;
	    } else {
		locked++;
		locked_size += e->mem_obj->inmem_hi;
	    }
	}			/* for, end of one bucket of hash table */
	qsort((char *) LRU_list,
	    list_count,
	    sizeof(StoreEntry *),
	    (QS *) compareLastRef);
	if (list_count > SWAP_LRU_REMOVE_COUNT)
	    list_count = SWAP_LRU_REMOVE_COUNT;		/* chop list */
	if (scan_count > SWAP_LRUSCAN_COUNT)
	    break;
    }				/* for */

#ifdef LOTSA_DEBUGGING
    /* end of candidate selection */
    debug(20, 2) ("storeGetSwapSpace: Current Size:   %7d kbytes\n",
	store_swap_size);
    debug(20, 2) ("storeGetSwapSpace: High W Mark:    %7d kbytes\n",
	store_swap_high);
    debug(20, 2) ("storeGetSwapSpace: Low W Mark:     %7d kbytes\n",
	store_swap_low);
    debug(20, 2) ("storeGetSwapSpace: Entry count:    %7d items\n",
	meta_data.store_entries);
    debug(20, 2) ("storeGetSwapSpace: Visited:        %7d buckets\n",
	i + 1);
    debug(20, 2) ("storeGetSwapSpace: Scanned:        %7d items\n",
	scanned);
    debug(20, 2) ("storeGetSwapSpace: Expired:        %7d items\n",
	expired);
    debug(20, 2) ("storeGetSwapSpace: Locked:         %7d items\n",
	locked);
    debug(20, 2) ("storeGetSwapSpace: Locked Space:   %7d bytes\n",
	locked_size);
    debug(20, 2) ("storeGetSwapSpace: Scan in array:  %7d bytes\n",
	scan_in_objs);
    debug(20, 2) ("storeGetSwapSpace: LRU candidate:  %7d items\n",
	LRU_list->index);
#endif /* LOTSA_DEBUGGING */

    for (i = 0; i < list_count; i++)
	removed += storeRelease(*(LRU_list + i));
    if (store_swap_size + kb_size <= store_swap_low)
	fReduceSwap = 0;
    debug(20, 2) ("storeGetSwapSpace: After Freeing Size:   %7d kbytes\n",
	store_swap_size);
    /* free the list */
    safe_free(LRU_list);

    if ((store_swap_size + kb_size > store_swap_high)) {
	i = 2;
	if (++swap_help > SWAP_MAX_HELP) {
	    debug(20, 0) ("WARNING: Repeated failures to free up disk space!\n");
	    i = 0;
	}
	debug(20, i) ("storeGetSwapSpace: Disk usage is over high water mark\n");
	debug(20, i) ("--> store_swap_high = %d KB\n", store_swap_high);
	debug(20, i) ("--> store_swap_size = %d KB\n", store_swap_size);
	debug(20, i) ("--> asking for        %d KB\n", kb_size);
    } else {
	swap_help = 0;
    }
    debug(20, 2) ("Removed %d objects\n", removed);
    return 0;
}


/* release an object from a cache */
/* return number of objects released. */
int
storeRelease(StoreEntry * e)
{
    StoreEntry *hentry = NULL;
    const char *hkey;
    debug(20, 3) ("storeRelease: Releasing: '%s'\n", e->key);
    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */
    if (storeEntryLocked(e)) {
	storeExpireNow(e);
	debug(20, 3) ("storeRelease: Only setting RELEASE_REQUEST bit\n");
	storeReleaseRequest(e);
	return 0;
    }
    /* check if coresponding HEAD object exists. */
    if (e->method == METHOD_GET) {
	hkey = storeGeneratePublicKey(e->url, METHOD_HEAD);
	if ((hentry = (StoreEntry *) hash_lookup(store_table, hkey)))
	    storeExpireNow(hentry);
    }
    if (store_rebuilding) {
	debug(20, 2) ("storeRelease: Delaying release until store is rebuilt: '%s'\n",
	    e->key ? e->key : e->url ? e->url : "NO URL");
	storeExpireNow(e);
	storeSetPrivateKey(e);
	BIT_SET(e->flag, RELEASE_REQUEST);
	return 0;
    }
    if (e->swap_status == SWAPOUT_DONE && (e->swap_file_number > -1)) {
	if (BIT_TEST(e->flag, ENTRY_VALIDATED))
	    storePutUnusedFileno(e->swap_file_number);
	storeDirUpdateSwapSize(e->swap_file_number, e->object_len, -1);
	e->swap_file_number = -1;
	HTTPCacheInfo->proto_purgeobject(HTTPCacheInfo,
	    urlParseProtocol(e->url),
	    e->object_len);
    }
    storeSetMemStatus(e, NOT_IN_MEMORY);
    storeHashDelete(e);
    storeLog(STORE_LOG_RELEASE, e);
    destroy_StoreEntry(e);
    return 1;
}

/* return 1 if a store entry is locked */
static int
storeEntryLocked(const StoreEntry * e)
{
    if (e->lock_count)
	return 1;
    if (e->swap_status == SWAPOUT_WRITING)
	return 1;
    if (e->store_status == STORE_PENDING)
	return 1;
    if (BIT_TEST(e->flag, ENTRY_SPECIAL))
	return 1;
    return 0;
}

static int
storeCopy(const StoreEntry * e, off_t stateoffset, size_t maxSize, char *buf, size_t * size)
{
    MemObject *mem = e->mem_obj;
    size_t s;
    assert(stateoffset >= mem->inmem_lo);
    s = memCopy(mem->data, stateoffset, buf, maxSize);
    assert(s);
    return *size = s;
}

/* check if there is any client waiting for this object at all */
/* return 1 if there is at least one client */
int
storeClientWaiting(const StoreEntry * e)
{
    int i;
    MemObject *mem = e->mem_obj;
    if (mem->clients) {
	for (i = 0; i < mem->nclients; i++) {
	    if (mem->clients[i].callback_data != NULL)
		return 1;
	}
    }
    return 0;
}

static struct _store_client *
storeClientListSearch(const MemObject * mem, void *data)
{
    int i;
    if (mem->clients) {
	for (i = 0; i < mem->nclients; i++) {
	    if (mem->clients[i].callback_data == data)
		return &mem->clients[i];
	}
    }
    return NULL;
}

/* add client with fd to client list */
int
storeClientListAdd(StoreEntry * e, void *data)
{
    int i;
    MemObject *mem = e->mem_obj;
    struct _store_client *oldlist = NULL;
    int oldsize;
    if (mem == NULL)
	mem = e->mem_obj = new_MemObject(urlClean(e->url));
    /* look for empty slot */
    if (mem->clients == NULL) {
	mem->nclients = MIN_CLIENT;
	mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
    }
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].callback_data == data)
	    return i;		/* its already here */
	if (mem->clients[i].callback_data == NULL)
	    break;
    }
    if (i == mem->nclients) {
	debug(20, 3) ("storeClientListAdd: Growing clients for '%s'\n", e->url);
	oldlist = mem->clients;
	oldsize = mem->nclients;
	mem->nclients <<= 1;
	mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
	for (i = 0; i < oldsize; i++)
	    mem->clients[i] = oldlist[i];
	safe_free(oldlist);
	i = oldsize;
    }
    mem->clients[i].callback_data = data;
    mem->clients[i].seen_offset = 0;
    mem->clients[i].copy_offset = 0;
    mem->clients[i].swapin_fd = -1;
    return i;
}

/* same to storeCopy but also register client fd and last requested offset
 * for each client */
void
storeClientCopy(StoreEntry * e,
    off_t seen_offset,
    off_t copy_offset,
    size_t size,
    char *buf,
    STCB * callback,
    void *data)
{
    size_t sz;
    MemObject *mem = e->mem_obj;
    struct _store_client *sc;
    static int recurse_detect = 0;
    assert(recurse_detect < 3);	/* could == 1 for IMS not modified's */
    debug(20, 3) ("storeClientCopy: %s, seen %d, want %d, size %d, cb %p, cbdata %p\n",
	e->key,
	(int) seen_offset,
	(int) copy_offset,
	(int) size,
	callback,
	data);
    sc = storeClientListSearch(mem, data);
    assert(sc != NULL);
    sc->copy_offset = copy_offset;
    sc->seen_offset = seen_offset;
    sc->callback = callback;
    sc->copy_buf = buf;
    sc->copy_size = size;
    sc->copy_offset = copy_offset;
    if (e->store_status == STORE_PENDING && seen_offset == mem->inmem_hi) {
	/* client has already seen this, wait for more */
	debug(20, 3) ("storeClientCopy: Waiting for more\n");
	return;
    }
    if (copy_offset >= mem->inmem_lo && mem->inmem_lo < mem->inmem_hi) {
	/* What the client wants is in memory */
	debug(20, 3) ("storeClientCopy: Copying from memory\n");
	sz = memCopy(mem->data, copy_offset, buf, size);
	recurse_detect++;
	sc->callback = NULL;
	callback(data, buf, sz);
    } else if (sc->swapin_fd < 0) {
	debug(20, 3) ("storeClientCopy: Need to open swap in file\n");
	/* gotta open the swapin file */
	assert(copy_offset == 0);
	storeSwapInStart(e, storeClientCopyFileOpened, sc);
    } else {
	debug(20, 3) ("storeClientCopy: reading from disk FD %d\n",
	    sc->swapin_fd);
	storeClientCopyFileRead(sc);
    }
    recurse_detect--;
}

static void
storeClientCopyFileOpened(int fd, void *data)
{
    struct _store_client *sc = data;
    if (fd < 0) {
	debug(20, 1) ("storeClientCopyFileOpened: failed\n");
	sc->callback(sc->callback_data, sc->copy_buf, -1);
	return;
    }
    sc->swapin_fd = fd;
    storeClientCopyFileRead(sc);
}

static void
storeClientCopyFileRead(struct _store_client *sc)
{
    file_read(sc->swapin_fd,
	sc->copy_buf,
	sc->copy_size,
	sc->copy_offset,
	storeClientCopyHandleRead,
	sc);
}

static void
storeClientCopyHandleRead(int fd, const char *buf, int len, int flag, void *data)
{
    struct _store_client *sc = data;
    debug(20, 3) ("storeClientCopyHandleRead: FD %d\n", fd);
    debug(20, 3) ("storeClientCopyHandleRead: buf = %p\n", buf);
    debug(20, 3) ("storeClientCopyHandleRead: len = %d\n", len);
    debug(20, 3) ("storeClientCopyHandleRead: flag = %d\n", flag);
    debug(20, 3) ("storeClientCopyHandleRead: data = %p\n", data);
    sc->callback(sc->callback_data, sc->copy_buf, len);
}


static int
storeEntryValidLength(const StoreEntry * e)
{
    int diff;
    int hdr_sz;
    int content_length;

    if (e->mem_obj == NULL)
	fatal_dump("storeEntryValidLength: NULL mem_obj");

    hdr_sz = e->mem_obj->reply->hdr_sz;
    content_length = e->mem_obj->reply->content_length;

    debug(20, 3) ("storeEntryValidLength: Checking '%s'\n", e->key);
    debug(20, 5) ("storeEntryValidLength:     object_len = %d\n", e->object_len);
    debug(20, 5) ("storeEntryValidLength:         hdr_sz = %d\n", hdr_sz);
    debug(20, 5) ("storeEntryValidLength: content_length = %d\n", content_length);

    if (content_length == 0) {
	debug(20, 5) ("storeEntryValidLength: Zero content length; assume valid; '%s'\n",
	    e->key);
	return 1;
    }
    if (hdr_sz == 0) {
	debug(20, 5) ("storeEntryValidLength: Zero header size; assume valid; '%s'\n",
	    e->key);
	return 1;
    }
    diff = hdr_sz + content_length - e->object_len;
    if (diff != 0) {
	debug(20, 3) ("storeEntryValidLength: %d bytes too %s; '%s'\n",
	    diff < 0 ? -diff : diff,
	    diff < 0 ? "small" : "big",
	    e->key);
	return 0;
    }
    return 1;
}

#if HAVE_RANDOM
#define squid_random random
#elif HAVE_LRAND48
#define squid_random lrand48
#else
#define squid_random rand
#endif

static void
storeRandomizeBuckets(void)
{
    int i;
    struct _bucketOrder *b;
    if (MaintBucketsOrder == NULL)
	MaintBucketsOrder = xcalloc(store_buckets, sizeof(struct _bucketOrder));
    for (i = 0; i < store_buckets; i++) {
	b = MaintBucketsOrder + i;
	b->bucket = (unsigned int) i;
	b->index = (int) squid_random();
    }
    qsort((char *) MaintBucketsOrder,
	store_buckets,
	sizeof(struct _bucketOrder),
	             (QS *) compareBucketOrder);
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
    if (i < 8192)
	store_buckets = 7951, store_maintain_rate = 10;
    else if (i < 12288)
	store_buckets = 12149, store_maintain_rate = 7;
    else if (i < 16384)
	store_buckets = 16231, store_maintain_rate = 5;
    else if (i < 32768)
	store_buckets = 33493, store_maintain_rate = 2;
    else
	store_buckets = 65357, store_maintain_rate = 1;
    store_maintain_buckets = 1;
    storeRandomizeBuckets();
    debug(20, 1) ("Using %d Store buckets, maintain %d bucket%s every %d second%s\n",
	store_buckets,
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
    storeCreateHashTable(urlcmp);
    if (strcmp((fname = Config.Log.store), "none") == 0)
	storelog_fd = -1;
    else
	storelog_fd = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL);
    if (storelog_fd < 0)
	debug(20, 1) ("Store logging disabled\n");
    storeVerifySwapDirs();
    storeDirOpenSwapLogs();
    if (!opt_zap_disk_store)
	storeStartRebuildFromDisk();
    else
	store_rebuilding = 0;
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

    store_pages_max = Config.Mem.maxSize / SM_PAGE_SIZE;
    store_pages_high = store_mem_high / SM_PAGE_SIZE;
    store_pages_low = store_mem_low / SM_PAGE_SIZE;
}

int
urlcmp(const char *url1, const char *url2)
{
    if (!url1 || !url2)
	fatal_dump("urlcmp: Got a NULL url pointer.");
    return (strcmp(url1, url2));
}

/* 
 * This routine is to be called by main loop in main.c.
 * It removes expired objects on only one bucket for each time called.
 * returns the number of objects removed
 *
 * This should get called 1/s from main().
 */
void
storeMaintainSwapSpace(void *unused)
{
    static time_t last_time = 0;
    static int bucket_index = 0;
    hash_link *link_ptr = NULL, *next = NULL;
    StoreEntry *e = NULL;
    int rm_obj = 0;
    int scan_buckets = 0;
    int scan_obj = 0;
    static struct _bucketOrder *b;

    eventAdd("storeMaintain", storeMaintainSwapSpace, NULL, 1);
    /* We can't delete objects while rebuilding swap */
    if (store_rebuilding)
	return;

    /* Purges expired objects, check one bucket on each calling */
    if (squid_curtime - last_time >= store_maintain_rate) {
	for (;;) {
	    if (scan_obj && scan_buckets >= store_maintain_buckets)
		break;
	    if (++scan_buckets > 100)
		break;
	    last_time = squid_curtime;
	    if (bucket_index >= store_buckets) {
		bucket_index = 0;
		scan_revolutions++;
		debug(51, 1) ("Completed %d full expiration scans of store table\n",
		    scan_revolutions);
		storeRandomizeBuckets();
	    }
	    b = MaintBucketsOrder + bucket_index++;
	    next = hash_get_bucket(store_table, b->bucket);
	    while ((link_ptr = next)) {
		scan_obj++;
		next = link_ptr->next;
		e = (StoreEntry *) link_ptr;
		if (!storeCheckExpired(e, 1))
		    continue;
		rm_obj += storeRelease(e);
	    }
	}
    }
    debug(51, rm_obj ? 2 : 9) ("Removed %d of %d objects from bucket %d\n",
	rm_obj, scan_obj, (int) b->bucket);
    /* Scan row of hash table each second and free storage if we're
     * over the high-water mark */
    storeGetSwapSpace(0);
}


/*
 *  storeWriteCleanLogs
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
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
    if (store_rebuilding) {
	debug(20, 1) ("Not currently OK to rewrite swap log.\n");
	debug(20, 1) ("storeWriteCleanLogs: Operation aborted.\n");
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
	safeunlink(new[dirn], 1);
	safeunlink(cln[dirn], 1);
	fd[dirn] = file_open(new[dirn],
	    O_WRONLY | O_CREAT | O_TRUNC,
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
    line = xcalloc(1, 16384);
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAPOUT_DONE)
	    continue;
	if (e->object_len <= 0)
	    continue;
	if (BIT_TEST(e->flag, RELEASE_REQUEST))
	    continue;
	if (BIT_TEST(e->flag, KEY_PRIVATE))
	    continue;
	dirn = storeDirNumber(e->swap_file_number);
	assert(dirn < Config.cacheSwap.n_configured);
	if (fd[dirn] < 0)
	    continue;
	snprintf(line, 16384, "%08x %08x %08x %08x %08x %9d %6d %08x %s\n",
	    (int) e->swap_file_number,
	    (int) e->timestamp,
	    (int) e->lastref,
	    (int) e->expires,
	    (int) e->lastmod,
	    e->object_len,
	    e->refcount,
	    e->flag,
	    e->url);
	if (write(fd[dirn], line, strlen(line)) < 0) {
	    debug(50, 0) ("storeWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
	    debug(20, 0) ("storeWriteCleanLogs: Current swap logfile not replaced.\n");
	    file_close(fd[dirn]);
	    fd[dirn] = -1;
	    safeunlink(cln[dirn], 0);
	    continue;
	}
	if ((++n & 0x3FFF) == 0) {
	    debug(20, 1) ("  %7d lines written so far.\n", n);
	}
    }
    safe_free(line);
    for (dirn = 0; dirn < Config.cacheSwap.n_configured; dirn++) {
	file_close(fd[dirn]);
	fd[dirn] = -1;
	if (rename(new[dirn], cur[dirn]) < 0) {
	    debug(50, 0) ("storeWriteCleanLogs: rename failed: %s\n",
		xstrerror());
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
		    O_WRONLY | O_CREAT | O_TRUNC, NULL, NULL));
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

int
storePendingNClients(const StoreEntry * e)
{
    int npend = 0;
    MemObject *mem = e->mem_obj;
    int i;
    if (mem == NULL)
	return 0;
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].callback_data == NULL)
	    continue;
	npend++;
    }
    return npend;
}

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
    storelog_fd = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL);
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

#if OLD_CODE
/*
 * Check if its okay to remove the memory data for this object, but 
 * leave the StoreEntry around.  Designed to be called from
 * storeUnlockObject() and storeSwapOutHandle().
 */
static int
storeCheckPurgeMem(const StoreEntry * e)
{
    if (storeEntryLocked(e))
	return 0;
    if (e->store_status != STORE_OK)
	return 0;
    if (e->swap_status != SWAPOUT_DONE)
	return 0;
    return 1;
}
#endif

static int
storeCheckExpired(const StoreEntry * e, int check_lru_age)
{
    time_t max_age;
    if (storeEntryLocked(e))
	return 0;
    if (BIT_TEST(e->flag, ENTRY_NEGCACHED) && squid_curtime >= e->expires)
	return 1;
    if (!check_lru_age)
	return 0;
    if ((max_age = storeExpiredReferenceAge()) <= 0)
	return 0;
    if (squid_curtime - e->lastref > max_age)
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
    if (Config.referenceAge == 0)
	return 0;
    x = (double) (store_swap_high - store_swap_size) / (store_swap_high - store_swap_low);
    x = x < 0.0 ? 0.0 : x > 1.0 ? 1.0 : x;
    z = pow((double) Config.referenceAge, x);
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
    BIT_SET(e->flag, ENTRY_NEGCACHED);
}

void
storeFreeMemory(void)
{
    StoreEntry *e;
    StoreEntry **list;
    int i = 0;
    int j;
    list = xcalloc(meta_data.store_entries, sizeof(StoreEntry *));
    e = (StoreEntry *) hash_first(store_table);
    while (e && i < meta_data.store_entries) {
	*(list + i) = e;
	i++;
	e = (StoreEntry *) hash_next(store_table);
    }
    for (j = 0; j < i; j++)
	destroy_StoreEntry(*(list + j));
    xfree(list);
    hashFreeMemory(store_table);
    store_table = NULL;
    safe_free(MaintBucketsOrder);
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
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	return 0;
    if (BIT_TEST(e->flag, ENTRY_NEGCACHED))
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

static int
storeGetUnusedFileno(void)
{
    int fn;
    if (fileno_stack_count < 1)
	return -1;
    fn = fileno_stack[--fileno_stack_count];
    storeDirMapBitSet(fn);
    return fn;
}

static void
storePutUnusedFileno(int fileno)
{
    assert(storeDirMapBitTest(fileno));
    storeDirMapBitReset(fileno);
    if (fileno_stack_count < FILENO_STACK_SIZE)
	fileno_stack[fileno_stack_count++] = fileno;
    else
	unlinkdUnlink(storeSwapFullPath(fileno, NULL));
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
    debug(20, 1) ("MemObject->data: %p\n",
	mem->data);
    debug(20, 1) ("MemObject->e_swap_buf: %p %s\n",
	mem->e_swap_buf,
	checkNullString(mem->e_swap_buf));
    debug(20, 1) ("MemObject->start_ping: %d.%06d\n",
	mem->start_ping.tv_sec,
	mem->start_ping.tv_usec);
    debug(20, 1) ("MemObject->e_swap_buf_len: %d\n",
	mem->e_swap_buf_len);
    debug(20, 1) ("MemObject->pending_list_size: %d\n",
	mem->pending_list_size);
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

static void
storeInMemAdd(StoreEntry * e)
{
    struct _mem_entry *m = xmalloc(sizeof(struct _mem_entry));
    debug(20, 3) ("storeInMemAdd: %s\n", e->url);
    assert(e->mem_obj->inmem_lo == 0);
    m->e = e;
    m->prev = NULL;
    m->next = inmem_head;
    if (inmem_head)
	inmem_head->prev = m;
    inmem_head = m;
    if (inmem_tail == NULL)
	inmem_tail = m;
    meta_data.hot_vm++;
}

static void
storeInMemDelete(StoreEntry * e)
{
    struct _mem_entry *m;
    for (m = inmem_tail; m; m = m->prev) {
	if (m->e == e)
	    break;
    }
    assert(m != NULL);
    debug(20, 3) ("storeInMemDelete: %s\n", e->url);
    if (m->next)
	m->next->prev = m->prev;
    if (m->prev)
	m->prev->next = m->next;
    if (m == inmem_head)
	inmem_head = m->next;
    if (m == inmem_tail)
	inmem_tail = m->prev;
    meta_data.hot_vm--;
}

/* NOTE, this function assumes only two mem states */
static void
storeSetMemStatus(StoreEntry * e, int new_status)
{
    if (new_status == e->mem_status)
	return;
    if (new_status == IN_MEMORY)
	storeInMemAdd(e);
    else
	storeInMemDelete(e);
    e->mem_status = new_status;
}
