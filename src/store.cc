
/*
 * $Id: store.cc,v 1.245 1997/05/23 20:45:58 wessels Exp $
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

/* 
 * Here is a summary of the routines which change mem_status and swap_status:
 * Added 11/18/95
 * 
 * Routine                  mem_status      swap_status         status 
 * ---------------------------------------------------------------------------
 * storeCreateEntry         NOT_IN_MEMORY   NO_SWAP
 * storeComplete            IN_MEMORY       NO_SWAP
 * storeSwapOutStart                        SWAPPING_OUT
 * storeSwapOutHandle(fail)                 NO_SWAP
 * storeSwapOutHandle(ok)                   SWAP_OK
 * ---------------------------------------------------------------------------
 * storeAddDiskRestore      NOT_IN_MEMORY   SWAP_OK
 * storeSwapInStart         SWAPPING_IN     
 * storeSwapInHandle(fail)  NOT_IN_MEMORY   
 * storeSwapInHandle(ok)    IN_MEMORY       
 * ---------------------------------------------------------------------------
 * storeAbort               IN_MEMORY       NO_SWAP
 * storePurgeMem            NOT_IN_MEMORY
 * ---------------------------------------------------------------------------
 * You can reclaim an object's space if it's:
 * storeGetSwapSpace       !SWAPPING_IN     !SWAPPING_OUT       !STORE_PENDING 
 *
 */

#include "squid.h"		/* goes first */
#include "filemap.h"
#include "store_dir.h"

#define REBUILD_TIMESTAMP_DELTA_MAX 2
#define SWAP_BUF		DISK_PAGE_SIZE

#define WITH_MEMOBJ	1
#define WITHOUT_MEMOBJ	0

#define STORE_IN_MEM_BUCKETS		(229)

#define STORE_LOG_CREATE	0
#define STORE_LOG_SWAPIN	1
#define STORE_LOG_SWAPOUT	2
#define STORE_LOG_RELEASE	3

#define ENTRY_INMEM_SIZE(X) ((X)->e_current_len - (X)->e_lowest_offset)

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
    "SWAPPING_IN",
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
    "NO_SWAP",
    "SWAPPING_OUT",
    "SWAP_OK"
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

typedef void (VCB) _PARAMS((void *, int));

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

/* initializtion flag */
int store_rebuilding = 1;

/* Static Functions */
static HashID storeCreateHashTable _PARAMS((int (*)_PARAMS((const char *, const char *))));
static int compareLastRef _PARAMS((StoreEntry **, StoreEntry **));
static int compareSize _PARAMS((StoreEntry **, StoreEntry **));
static int compareBucketOrder _PARAMS((struct _bucketOrder *, struct _bucketOrder *));
static int storeCheckExpired _PARAMS((const StoreEntry *, int flag));
static int storeCheckPurgeMem _PARAMS((const StoreEntry *));
static int storeClientListSearch _PARAMS((const MemObject *, void *));
static int storeCopy _PARAMS((const StoreEntry *, int, int, char *, int *));
static int storeEntryLocked _PARAMS((const StoreEntry *));
static int storeEntryValidLength _PARAMS((const StoreEntry *));
static void storeGetMemSpace _PARAMS((int));
static int storeHashDelete _PARAMS((StoreEntry *));
static int storeShouldPurgeMem _PARAMS((const StoreEntry *));
static DRCB storeSwapInHandle;
static VCB storeSwapInValidateComplete;
static void storeSwapInStartComplete _PARAMS((void *, int));
static int swapInError _PARAMS((int, StoreEntry *));
static mem_ptr new_MemObjectData _PARAMS((void));
static MemObject *new_MemObject _PARAMS((void));
static StoreEntry *new_StoreEntry _PARAMS((int));
static StoreEntry *storeAddDiskRestore _PARAMS((const char *,
	int,
	int,
	time_t,
	time_t,
	time_t,
	int));
static StoreEntry *storeGetInMemFirst _PARAMS((void));
static StoreEntry *storeGetInMemNext _PARAMS((void));
static unsigned int storeGetBucketNum _PARAMS((void));
static void destroy_MemObject _PARAMS((MemObject *));
static void destroy_MemObjectData _PARAMS((MemObject *));
static void destroy_StoreEntry _PARAMS((StoreEntry *));
static void storeDeleteBehind _PARAMS((StoreEntry *));
static void storePurgeMem _PARAMS((StoreEntry *));
static void storeSetMemStatus _PARAMS((StoreEntry *, mem_status_t));
static void storeStartRebuildFromDisk _PARAMS((void));
static void storeSwapOutStart _PARAMS((StoreEntry * e));
static void storeSwapOutStartComplete _PARAMS((void *, int));
static DWCB storeSwapOutHandle;
static void storeHashMemInsert _PARAMS((StoreEntry *));
static void storeHashMemDelete _PARAMS((StoreEntry *));
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

/* Now, this table is inaccessible to outsider. They have to use a method
 * to access a value in internal storage data structure. */
static HashID store_table = 0;
/* hash table for in-memory-only objects */
static HashID in_mem_table = 0;

/* current memory storage size */
unsigned long store_mem_size = 0;

static int store_pages_max = 0;
static int store_pages_high = 0;
static int store_pages_low = 0;

/* current file name, swap file, use number as a filename */
int store_swap_size = 0;	/* kilobytes !! */
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

/* Dirty/Clean rebuild status parameter */
static int store_validating = 0;

static MemObject *
new_MemObject(void)
{
    MemObject *mem = get_free_mem_obj();
    mem->reply = xcalloc(1, sizeof(struct _http_reply));
    mem->reply->date = -2;
    mem->reply->expires = -2;
    mem->reply->last_modified = -2;
    mem->request = NULL;
    meta_data.mem_obj_count++;
    meta_data.misc += sizeof(struct _http_reply);
    debug(20, 3, "new_MemObject: returning %p\n", mem);
    return mem;
}

static StoreEntry *
new_StoreEntry(int mem_obj_flag)
{
    StoreEntry *e = NULL;

    e = xcalloc(1, sizeof(StoreEntry));
    meta_data.store_entries++;
    if (mem_obj_flag)
	e->mem_obj = new_MemObject();
    debug(20, 3, "new_StoreEntry: returning %p\n", e);
    return e;
}

static void
destroy_MemObject(MemObject * mem)
{
    debug(20, 3, "destroy_MemObject: destroying %p\n", mem);
    destroy_MemObjectData(mem);
    safe_free(mem->clients);
    safe_free(mem->request_hdr);
    safe_free(mem->reply);
    safe_free(mem->e_abort_msg);
    requestUnlink(mem->request);
    mem->request = NULL;
    put_free_mem_obj(mem);
    meta_data.mem_obj_count--;
    meta_data.misc -= sizeof(struct _http_reply);
}

static void
destroy_StoreEntry(StoreEntry * e)
{
    debug(20, 3, "destroy_StoreEntry: destroying %p\n", e);
    if (!e) {
	debug_trap("destroy_StoreEntry: NULL Entry");
	return;
    }
    if (e->mem_obj)
	destroy_MemObject(e->mem_obj);
    if (e->url) {
	meta_data.url_strings -= strlen(e->url);
	safe_free(e->url);
    } else {
	debug(20, 3, "destroy_StoreEntry: WARNING: Entry without URL string!\n");
    }
    if (BIT_TEST(e->flag, KEY_URL))
	e->key = NULL;
    else
	safe_free(e->key);
    xfree(e);
    meta_data.store_entries--;
}

static mem_ptr
new_MemObjectData(void)
{
    debug(20, 3, "new_MemObjectData: calling memInit()\n");
    meta_data.mem_data_count++;
    return memInit();
}

static void
destroy_MemObjectData(MemObject * mem)
{
    debug(20, 3, "destroy_MemObjectData: destroying %p, %d bytes\n",
	mem->data, mem->e_current_len);
    store_mem_size -= ENTRY_INMEM_SIZE(mem);
    if (mem->data) {
	memFree(mem->data);
	mem->data = NULL;
	meta_data.mem_data_count--;
    }
    mem->e_current_len = 0;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

/*
 * Create 2 hash tables, "table" has all objects, "in_mem_table" has only
 * objects in the memory.
 */

static HashID
storeCreateHashTable(int (*cmp_func) (const char *, const char *))
{
    store_table = hash_create(cmp_func, store_buckets, hash4);
    in_mem_table = hash_create(cmp_func, STORE_IN_MEM_BUCKETS, hash4);
    return store_table;
}

static void
storeHashMemInsert(StoreEntry * e)
{
    hash_insert(in_mem_table, e->key, e);
    meta_data.hot_vm++;
}

static void
storeHashMemDelete(StoreEntry * e)
{
    hash_link *hptr = hash_lookup(in_mem_table, e->key);
    if (hptr == NULL) {
	debug_trap("storeHashMemDelete: key not found");
	return;
    }
    hash_delete_link(in_mem_table, hptr);
    meta_data.hot_vm--;
}

static int
storeHashInsert(StoreEntry * e)
{
    debug(20, 3, "storeHashInsert: Inserting Entry %p key '%s'\n",
	e, e->key);
    if (e->mem_status == IN_MEMORY)
	storeHashMemInsert(e);
    return hash_join(store_table, (hash_link *) e);
}

static int
storeHashDelete(StoreEntry * e)
{
    if (e->mem_status == IN_MEMORY)
	storeHashMemDelete(e);
    return hash_remove_link(store_table, (hash_link *) e);
}

/*
 * maintain the in-mem hash table according to the changes of mem_status
 * This routine replaces the instruction "e->store_status = status;"
 */
static void
storeSetMemStatus(StoreEntry * e, mem_status_t status)
{
    if (e->key == NULL) {
	debug_trap("storeSetMemStatus: NULL key");
	return;
    } else if (status != IN_MEMORY && e->mem_status == IN_MEMORY)
	storeHashMemDelete(e);
    else if (status == IN_MEMORY && e->mem_status != IN_MEMORY)
	storeHashMemInsert(e);
    e->mem_status = status;
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
    reply = mem->reply;
    sprintf(logmsg, "%9d.%03d %-7s %08X %4d %9d %9d %9d %s %d/%d %s %s\n",
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
	mem->e_current_len - mem->reply->hdr_sz,
	RequestMethodStr[e->method],
	e->key);
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
    debug(20, 3, "storePurgeMem: Freeing memory-copy of %s\n", e->key);
    if (e->mem_obj == NULL)
	return;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    destroy_MemObject(e->mem_obj);
    e->mem_obj = NULL;
}

void
storeLockObject(StoreEntry * e)
{
    e->lock_count++;
    debug(20, 3, "storeLockObject: key '%s' count=%d\n",
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
    debug(20, 3, "storeReleaseRequest: '%s'\n", e->key);
    BIT_SET(e->flag, RELEASE_REQUEST);
    storeSetPrivateKey(e);
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */
int
storeUnlockObject(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    e->lock_count--;
    debug(20, 3, "storeUnlockObject: key '%s' count=%d\n",
	e->key, e->lock_count);
    if (e->lock_count)
	return (int) e->lock_count;
    if (e->store_status == STORE_PENDING) {
	if (BIT_TEST(e->flag, ENTRY_DISPATCHED)) {
	    debug_trap("storeUnlockObject: PENDING and DISPATCHED with 0 locks");
	    debug(20, 1, "   --> Key '%s'\n", e->key);
	    e->store_status = STORE_ABORTED;
	} else {
	    BIT_SET(e->flag, RELEASE_REQUEST);
	}
    }
    if (storePendingNClients(e) > 0)
	debug_trap("storeUnlockObject: unlocked entry with pending clients\n");
    if (BIT_TEST(e->flag, RELEASE_REQUEST)) {
	storeRelease(e);
    } else if (BIT_TEST(e->flag, ABORT_MSG_PENDING)) {
	/* This is where the negative cache gets storeAppended */
	/* Briefly lock to replace content with abort message */
	e->lock_count++;
	destroy_MemObjectData(mem);
	e->object_len = 0;
	mem->data = new_MemObjectData();
	storeAppend(e, mem->e_abort_msg, strlen(mem->e_abort_msg));
	e->object_len = mem->e_current_len = strlen(mem->e_abort_msg);
	BIT_RESET(e->flag, ABORT_MSG_PENDING);
	e->lock_count--;
    } else if (storeShouldPurgeMem(e)) {
	storePurgeMem(e);
    }
    return 0;
}

/* Lookup an object in the cache. 
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *
storeGet(const char *url)
{
    debug(20, 3, "storeGet: looking up %s\n", url);
    return (StoreEntry *) hash_lookup(store_table, url);
}

unsigned int
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
    debug(20, 3, "storeGeneratePrivateKey: '%s'\n", url);
    key_temp_buffer[0] = '\0';
    sprintf(key_temp_buffer, "%d/%s/%s",
	num,
	RequestMethodStr[method],
	url);
    return key_temp_buffer;
}

const char *
storeGeneratePublicKey(const char *url, method_t method)
{
    debug(20, 3, "storeGeneratePublicKey: type=%d %s\n", method, url);
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
	sprintf(key_temp_buffer, "/%s/%s", RequestMethodStr[method], url);
	return key_temp_buffer;
	/* NOTREACHED */
	break;
    default:
	debug_trap("storeGeneratePublicKey: Unsupported request method");
	break;
    }
    return NULL;
}

static void
storeSetPrivateKey(StoreEntry * e)
{
    hash_link *table_entry = NULL;
    const char *newkey = NULL;
    if (e->key && BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already private */
    newkey = storeGeneratePrivateKey(e->url, e->method, 0);
    if ((table_entry = hash_lookup(store_table, newkey))) {
	debug_trap("storeSetPrivateKey: duplicate private key");
	return;
    }
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
	debug(20, 3, "storeSetPublicKey: Making old '%s' private.\n", newkey);
	e2 = (StoreEntry *) table_entry;
	storeSetPrivateKey(e2);
	storeRelease(e2);
	if (loop_detect++ == 10)
	    fatal_dump("storeSetPublicKey() is looping!!");
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
storeCreateEntry(const char *url,
    const char *req_hdr,
    int req_hdr_sz,
    int flags,
    method_t method)
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    debug(20, 3, "storeCreateEntry: '%s' icp flags=%x\n", url, flags);

    e = new_StoreEntry(WITH_MEMOBJ);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    e->url = xstrdup(url);
    meta_data.url_strings += strlen(url);
    e->method = method;
    if (req_hdr) {
	mem->request_hdr_sz = req_hdr_sz;
	mem->request_hdr = xmalloc(req_hdr_sz + 1);
	xmemcpy(mem->request_hdr, req_hdr, req_hdr_sz);
	*(mem->request_hdr + req_hdr_sz) = '\0';
    }
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
    if (neighbors_do_private_keys || !BIT_TEST(flags, REQ_HIERARCHICAL))
	storeSetPrivateKey(e);
    else
	storeSetPublicKey(e);
    BIT_SET(e->flag, ENTRY_HTML);

    e->store_status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = NO_SWAP;
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
storeAddDiskRestore(const char *url, int file_number, int size, time_t expires, time_t timestamp, time_t lastmod, int clean)
{
    StoreEntry *e = NULL;

    debug(20, 5, "StoreAddDiskRestore: '%s': size %d: expires %d: fileno=%08X\n",
	url, size, expires, file_number);

    /* if you call this you'd better be sure file_number is not 
     * already in use! */

    meta_data.url_strings += strlen(url);

    e = new_StoreEntry(WITHOUT_MEMOBJ);
    e->url = xstrdup(url);
    e->method = METHOD_GET;
    storeSetPublicKey(e);
    BIT_SET(e->flag, ENTRY_CACHABLE);
    BIT_RESET(e->flag, RELEASE_REQUEST);
    BIT_SET(e->flag, ENTRY_HTML);
    e->store_status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAP_OK;
    e->swap_file_number = file_number;
    e->object_len = size;
    e->lock_count = 0;
    BIT_RESET(e->flag, CLIENT_ABORT_REQUEST);
    e->refcount = 0;
    e->lastref = timestamp;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
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
    int i;
    MemObject *mem = e->mem_obj;
    struct _store_client *sc;
    if (mem == NULL)
	return 0;
    debug(20, 3, "storeUnregister: called for '%s'\n", e->key);
    if ((i = storeClientListSearch(mem, data)) < 0)
	return 0;
    sc = &mem->clients[i];
    sc->seen_offset = 0;
    sc->copy_offset = 0;
    sc->callback = NULL;
    sc->callback_data = NULL;
    debug(20, 9, "storeUnregister: returning 1\n");
    return 1;
}

int
storeGetLowestReaderOffset(const StoreEntry * entry)
{
    const MemObject *mem = entry->mem_obj;
    int lowest = mem->e_current_len;
    int i;
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].callback_data == NULL)
	    continue;
	if (mem->clients[i].copy_offset < lowest)
	    lowest = mem->clients[i].copy_offset;
    }
    return lowest;
}

/* Call to delete behind upto "target lowest offset"
 * also, update e_lowest_offset  */
static void
storeDeleteBehind(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    int old_lowest_offset = mem->e_lowest_offset;
    int new_lowest_offset;
    int target_offset = storeGetLowestReaderOffset(e);
    if (target_offset == 0)
	return;
    new_lowest_offset = (int) memFreeDataUpto(mem->data,
	target_offset);
    store_mem_size -= new_lowest_offset - old_lowest_offset;
    mem->e_lowest_offset = new_lowest_offset;
}

/* Call handlers waiting for  data to be appended to E. */
void
InvokeHandlers(StoreEntry * e)
{
    int i;
    MemObject *mem = e->mem_obj;
    STCB *callback = NULL;
    struct _store_client *sc;
    size_t size;
    if (mem->clients == NULL && mem->nclients) {
	debug_trap("InvokeHandlers: NULL mem->clients");
	return;
    }
    /* walk the entire list looking for valid callbacks */
    for (i = 0; i < mem->nclients; i++) {
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
	callback(sc->callback_data, sc->copy_buf, size);
    }
}

/* Mark object as expired */
void
storeExpireNow(StoreEntry * e)
{
    debug(20, 3, "storeExpireNow: '%s'\n", e->key);
    e->expires = squid_curtime;
}

/* switch object to deleting behind mode call by
 * retrieval module when object gets too big.  */
void
storeStartDeleteBehind(StoreEntry * e)
{
    if (BIT_TEST(e->flag, DELETE_BEHIND))
	return;
    debug(20, e->mem_obj->e_current_len ? 1 : 3,
	"storeStartDeleteBehind: '%s' at %d bytes\n",
	e->url, e->mem_obj->e_current_len);
    storeSetPrivateKey(e);
    BIT_SET(e->flag, DELETE_BEHIND);
    storeReleaseRequest(e);
    BIT_RESET(e->flag, ENTRY_CACHABLE);
    storeExpireNow(e);
}

/* Append incoming data from a primary server to an entry. */
void
storeAppend(StoreEntry * e, const char *buf, int len)
{
    MemObject *mem = e->mem_obj;
    assert(mem != NULL);
    assert(len >= 0);
    if (len) {
	debug(20, 5, "storeAppend: appending %d bytes for '%s'\n", len, e->key);
	storeGetMemSpace(len);
	if (sm_stats.n_pages_in_use > store_pages_low) {
	    if (mem->e_current_len > Config.Store.maxObjectSize)
		storeStartDeleteBehind(e);
	}
	store_mem_size += len;
	memAppend(mem->data, buf, len);
	mem->e_current_len += len;
    }
    if (e->store_status != STORE_ABORTED && !BIT_TEST(e->flag, DELAY_SENDING))
	InvokeHandlers(e);
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
    vsprintf(buf, fmt, args);
    storeAppend(e, buf, strlen(buf));
    va_end(args);
}

/* swapping in handle */
static void
storeSwapInHandle(int u1, const char *buf, int len, int flag, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    assert(mem);
    debug(20, 2, "storeSwapInHandle: '%s'\n", e->key);
    if ((flag < 0) && (flag != DISK_EOF)) {
	debug(20, 0, "storeSwapInHandle: SwapIn failure (err code = %d).\n", flag);
	put_free_8k_page(mem->e_swap_buf);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	file_close(mem->swapin_fd);
	swapInError(-1, e);	/* Invokes storeAbort() and completes the I/O */
	return;
    }
    debug(20, 5, "storeSwapInHandle: e->swap_offset   = %d\n", mem->swap_offset);
    debug(20, 5, "storeSwapInHandle: e->e_current_len = %d\n", mem->e_current_len);
    debug(20, 5, "storeSwapInHandle: e->object_len    = %d\n", e->object_len);
    if (len && mem->swap_offset == 0)
	httpParseReplyHeaders(buf, mem->reply);
    /* Assumes we got all the headers in one read() */
    /* always call these, even if len == 0 */
    mem->swap_offset += len;
    storeAppend(e, buf, len);
    if (mem->e_current_len < e->object_len && flag != DISK_EOF) {
	/* some more data to swap in, reschedule */
	file_read(mem->swapin_fd,
	    mem->e_swap_buf,
	    SWAP_BUF,
	    mem->swap_offset,
	    storeSwapInHandle,
	    e);
	return;
    }
    if (mem->e_current_len > e->object_len)
	debug_trap("storeSwapInHandle: Too much data read!");
    /* complete swapping in */
    storeSetMemStatus(e, IN_MEMORY);
    put_free_8k_page(mem->e_swap_buf);
    file_close(mem->swapin_fd);
    storeLog(STORE_LOG_SWAPIN, e);
    debug(20, 5, "storeSwapInHandle: SwapIn complete: '%s' from %s.\n",
	e->url, storeSwapFullPath(e->swap_file_number, NULL));
    if (mem->e_current_len != e->object_len) {
	debug_trap("storeSwapInHandle: Object size mismatch");
	debug(20, 0, "  --> '%s'\n", e->url);
	debug(20, 0, "  --> Expecting %d bytes from file: %s\n", e->object_len,
	    storeSwapFullPath(e->swap_file_number, NULL));
	debug(20, 0, "  --> Only read %d bytes\n",
	    mem->e_current_len);
    }
    e->lock_count++;		/* lock while calling handler */
    InvokeHandlers(e);		/* once more after mem_status state change */
    e->lock_count--;
    if (BIT_TEST(e->flag, RELEASE_REQUEST)) {
	storeRelease(e);
    } else if ((mem = e->mem_obj)) {
	requestUnlink(mem->request);
	mem->request = NULL;
    }
}

/* start swapping in */
void
storeSwapInStart(StoreEntry * e, SIH * callback, void *callback_data)
{
    swapin_ctrl_t *ctrlp;
    if (e->mem_status != NOT_IN_MEMORY) {
	callback(callback_data, 0);
	return;
    }
    if (e->store_status == STORE_PENDING) {
	callback(callback_data, 0);
	return;
    }
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED)) {
        if (storeDirMapBitTest(e->swap_file_number)) {
	    /* someone took our file while we weren't looking */
	    callback(callback_data, -1);
	    return;
	}
    }
    assert(e->swap_status == SWAP_OK);
    assert(e->swap_file_number >= 0);
    assert(e->mem_obj == NULL);
    e->mem_obj = new_MemObject();
    ctrlp = xmalloc(sizeof(swapin_ctrl_t));
    ctrlp->e = e;
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;
    if (BIT_TEST(e->flag, ENTRY_VALIDATED))
	storeSwapInValidateComplete(ctrlp, 0);
    else
	storeValidate(e, storeSwapInValidateComplete, ctrlp);
}


static void
storeSwapInValidateComplete(void *data, int status)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e;
    e = ctrlp->e;
    assert(e->mem_status == NOT_IN_MEMORY);
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED)) {
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (ctrlp->callback_data, -1);
	xfree(ctrlp);
	return;
    }
    ctrlp->path = xstrdup(storeSwapFullPath(e->swap_file_number, NULL));
    file_open(ctrlp->path, O_RDONLY, storeSwapInStartComplete, ctrlp);
}

static void
storeSwapInStartComplete(void *data, int fd)
{
    swapin_ctrl_t *ctrlp = (swapin_ctrl_t *) data;
    StoreEntry *e = ctrlp->e;
    MemObject *mem = e->mem_obj;
    assert(e->mem_obj != NULL);
    assert(e->mem_status == NOT_IN_MEMORY);
    assert(e->swap_status == SWAP_OK);
    if (fd < 0) {
	debug(20, 0, "storeSwapInStartComplete: Failed for '%s'\n", e->url);
	/* Invoke a store abort that should free the memory object */
	(ctrlp->callback) (ctrlp->callback_data, -1);
	xfree(ctrlp->path);
	xfree(ctrlp);
	return;
    }
    storeSetMemStatus(e, SWAPPING_IN);
    mem->swapin_fd = (short) fd;
    debug(20, 5, "storeSwapInStart: initialized swap file '%s' for '%s'\n",
	ctrlp->path, e->url);
    mem->data = new_MemObjectData();
    mem->swap_offset = 0;
    mem->e_swap_buf = get_free_8k_page();
    /* start swapping daemon */
    file_read(fd,
	mem->e_swap_buf,
	SWAP_BUF,
	mem->swap_offset,
	storeSwapInHandle,
	e);
    (ctrlp->callback) (ctrlp->callback_data, 0);
    xfree(ctrlp->path);
    xfree(ctrlp);
}

static void
storeSwapOutHandle(int fd, int flag, size_t len, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    debug(20, 3, "storeSwapOutHandle: '%s'\n", e->key);
    if (mem == NULL)
	fatal_dump("storeSwapOutHandle: NULL mem_obj");
    if (flag < 0) {
	debug(20, 1, "storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = NO_SWAP;
	put_free_8k_page(mem->e_swap_buf);
	file_close(fd);
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
    debug(20, 6, "storeSwapOutHandle: e->swap_offset    = %d\n", mem->swap_offset);
    debug(20, 6, "storeSwapOutHandle: e->e_swap_buf_len = %d\n", mem->e_swap_buf_len);
    debug(20, 6, "storeSwapOutHandle: e->object_len     = %d\n", e->object_len);
    debug(20, 6, "storeSwapOutHandle: store_swap_size   = %dk\n", store_swap_size);
    mem->swap_offset += mem->e_swap_buf_len;
    /* round up */
    storeDirUpdateSwapSize(e->swap_file_number, mem->e_swap_buf_len, 1);
    if (mem->swap_offset >= e->object_len) {
	/* swapping complete */
	e->swap_status = SWAP_OK;
	file_close(mem->swapout_fd);
	storeLog(STORE_LOG_SWAPOUT, e);
	debug(20, 5, "storeSwapOutHandle: SwapOut complete: '%s' to %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	put_free_8k_page(mem->e_swap_buf);
	storeDirSwapLog(e);
	HTTPCacheInfo->proto_newobject(HTTPCacheInfo,
	    mem->request->protocol,
	    e->object_len,
	    FALSE);
	/* check if it's request to be released. */
	if (BIT_TEST(e->flag, RELEASE_REQUEST))
	    storeRelease(e);
	else if (storeShouldPurgeMem(e))
	    storePurgeMem(e);
	else {
	    requestUnlink(mem->request);
	    mem->request = NULL;
	}
	return;
    }
    /* write some more data, reschedule itself. */
    if (storeCopy(e, mem->swap_offset, SWAP_BUF, mem->e_swap_buf, &(mem->e_swap_buf_len)) < 0) {
	debug(20, 1, "storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = NO_SWAP;
	put_free_8k_page(mem->e_swap_buf);
	file_close(fd);
	if (e->swap_file_number != -1) {
	    storeDirMapBitReset(e->swap_file_number);
	    safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 0);
	    e->swap_file_number = -1;
	}
	storeRelease(e);
	return;
    }
    file_write(mem->swapout_fd,
	mem->e_swap_buf,
	mem->e_swap_buf_len,
	storeSwapOutHandle,
	e,
	NULL);
    return;
}

/* start swapping object to disk */
static void
storeSwapOutStart(StoreEntry * e)
{
    swapout_ctrl_t *ctrlp;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN);
    if ((e->swap_file_number = storeGetUnusedFileno()) < 0)
	e->swap_file_number = storeDirMapAllocate();
    storeSwapFullPath(e->swap_file_number, swapfilename);
    ctrlp = xmalloc(sizeof(swapout_ctrl_t));
    ctrlp->swapfilename = xstrdup(swapfilename);
    ctrlp->e = e;
    ctrlp->oldswapstatus = e->swap_status;
    e->swap_status = SWAPPING_OUT;
    file_open(swapfilename,
	O_WRONLY | O_CREAT | O_TRUNC,
	storeSwapOutStartComplete,
	ctrlp);
}

static void
storeSwapOutStartComplete(void *data, int fd)
{
    swapout_ctrl_t *ctrlp = data;
    int oldswapstatus = ctrlp->oldswapstatus;
    char *swapfilename = ctrlp->swapfilename;
    StoreEntry *e = ctrlp->e;
    int x;
    MemObject *mem;
    xfree(ctrlp);
    if (fd < 0) {
	debug(20, 0, "storeSwapOutStart: Unable to open swapfile: %s\n",
	    swapfilename);
	storeDirMapBitReset(e->swap_file_number);
	e->swap_file_number = -1;
	if (e->swap_status == SWAPPING_OUT)
	    e->swap_status = oldswapstatus;
	xfree(swapfilename);
	return;
    }
    mem = e->mem_obj;
    mem->swapout_fd = (short) fd;
    debug(20, 5, "storeSwapOutStart: Begin SwapOut '%s' to FD %d FILE %s.\n",
	e->url, fd, swapfilename);
    debug(20, 5, "swap_file_number=%08X\n", e->swap_file_number);
    e->swap_status = SWAPPING_OUT;
    mem->swap_offset = 0;
    mem->e_swap_buf = get_free_8k_page();
    mem->e_swap_buf_len = 0;
    x = storeCopy(e,
	0,
	SWAP_BUF,
	mem->e_swap_buf,
	&mem->e_swap_buf_len);
    if (x < 0) {
	debug(20, 1, "storeCopy returned %d for '%s'\n", x, e->key);
	e->swap_file_number = -1;
	file_close(fd);
	storeDirMapBitReset(e->swap_file_number);
	e->swap_file_number = -1;
	safeunlink(swapfilename, 1);
	if (e->swap_status == SWAPPING_OUT)
	    e->swap_status = oldswapstatus;
	xfree(swapfilename);
	return;
    }
    /* start swapping daemon */
    x = file_write(mem->swapout_fd,
	mem->e_swap_buf,
	mem->e_swap_buf_len,
	storeSwapOutHandle,
	e,
	NULL);
    if (x != DISK_OK)
	fatal_dump(NULL);	/* This shouldn't happen */
    xfree(swapfilename);
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
    time_t lastmod;
    int scan1;
    int scan2;
    int scan3;
    int scan4;
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
	    debug(20, 1, "Done reading Cache Dir #%d swap log\n", d->dirn);
	    fclose(d->log);
	    d->log = NULL;
	    storeDirCloseTmpSwapLog(d->dirn);
	    RB->rebuild_dir = d->next;
	    safe_free(d);
	    eventAdd("storeRebuild", storeDoRebuildFromDisk, RB, 0);
	    return;
	}
	if ((++RB->linecount & 0x3FFF) == 0)
	    debug(20, 1, "  %7d Lines read so far.\n", RB->linecount);
	debug(20, 9, "line_in: %s", RB->line_in);
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
	x = sscanf(RB->line_in, "%x %x %x %x %d %s",
	    &sfileno,		/* swap_file_number */
	    &scan1,		/* timestamp */
	    &scan2,		/* expires */
	    &scan3,		/* last modified */
	    &scan4,		/* size */
	    url);		/* url */
	if (x < 1)
	    continue;
	storeSwapFullPath(sfileno, swapfile);
	if (x != 6)
	    continue;
	if (sfileno < 0)
	    continue;
	sfileno = storeDirProperFileno(d->dirn, sfileno);
	timestamp = (time_t) scan1;
	expires = (time_t) scan2;
	lastmod = (time_t) scan3;
	size = (off_t) scan4;

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
	    continue;
	} else if (used) {
	    /* swapfile in use, not by this URL, log entry is newer */
	    /* This is sorta bad: the log entry should NOT be newer at this
	     * point.  If the log is dirty, the filesize check should have
	     * caught this.  If the log is clean, there should never be a
	     * newer entry. */
	    debug(20, 1, "WARNING: newer swaplog entry for fileno %08X\n",
		sfileno);
	    /* I'm tempted to remove the swapfile here just to be safe,
	     * but there is a bad race condition in the NOVM version if
	     * the swapfile has recently been opened for writing, but
	     * not yet opened for reading.  Because we can't map
	     * swapfiles back to StoreEntrys, we don't know the state
	     * of the entry using that file.  */
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
	    lastmod,
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
	    debug(20, 1, "  Completed Validation Procedure\n");
	    debug(20, 1, "  Validated %d Entries\n", validnum);
	    store_validating = 0;
	    return;
	}
	link_ptr = hash_get_bucket(store_table, bucketnum);
	for (; link_ptr; link_ptr = link_ptr->next) {
	    e = (StoreEntry *) link_ptr;
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
    if (e == NULL) {
	xfree(curr->key);
	xfree(curr);
	eventAdd("storeCleanup", storeCleanup, NULL, 0);
	return;
    }
    if ((validnum % 4096) == 0)
	debug(20, 1, "  %7d Entries Validated so far.\n", validnum);
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED)) {
	storeValidate(e, storeCleanupComplete, e);
	validnum++;
    }
    xfree(curr->key);
    xfree(curr);
    eventAdd("storeCleanup", storeCleanup, NULL, 0);
}

static void
storeCleanupComplete(void *data, int status)
{
    StoreEntry *e = data;
    if (!BIT_TEST(e->flag, ENTRY_VALIDATED))
	storeRelease(e);
}

static void
storeValidate(StoreEntry * e, VCB callback, void *callback_data)
{
    valid_ctrl_t *ctrlp;
    char *path;
    struct stat *sb;
    int x;
    assert(!BIT_TEST(e->flag, ENTRY_VALIDATED));
    if (e->swap_file_number < 0) {
	BIT_RESET(e->flag, ENTRY_VALIDATED);
	callback(callback_data, -1);
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
    (ctrlp->callback) (ctrlp->callback_data, retcode);
    xfree(sb);
    xfree(ctrlp);
}

/* meta data recreated from disk image in swap directory */
static void
storeRebuiltFromDisk(struct storeRebuildState *data)
{
    time_t r;
    time_t stop;
    stop = getCurrentTime();
    r = stop - data->start;
    debug(20, 1, "Finished rebuilding storage from disk image.\n");
    debug(20, 1, "  %7d Lines read from previous logfile.\n", data->linecount);
    debug(20, 1, "  %7d Objects loaded.\n", data->objcount);
    debug(20, 1, "  %7d Objects expired.\n", data->expcount);
    debug(20, 1, "  %7d Duplicate URLs purged.\n", data->dupcount);
    debug(20, 1, "  %7d Swapfile clashes avoided.\n", data->clashcount);
    debug(20, 1, "  Took %d seconds (%6.1lf objects/sec).\n",
	r > 0 ? r : 0, (double) data->objcount / (r > 0 ? r : 1));
    debug(20, 1, "  store_swap_size = %dk\n", store_swap_size);
    store_rebuilding = 0;
    safe_free(data->line_in);
    safe_free(data);
    if (store_validating) {
	debug(20, 1, "Beginning Validation Procedure\n");
	eventAdd("storeCleanup", storeCleanup, NULL, 0);
    }
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
    for (i = 0; i < ncache_dirs; i++) {
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
	    store_validating = 1;
	debug(20, 1, "Rebuilding storage in Cache Dir #%d (%s)\n",
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
storeCheckSwapable(StoreEntry * e)
{
    if (e->method != METHOD_GET) {
	debug(20, 2, "storeCheckSwapable: NO: non-GET method\n");
    } else if (!BIT_TEST(e->flag, ENTRY_CACHABLE)) {
	debug(20, 2, "storeCheckSwapable: NO: not cachable\n");
    } else if (BIT_TEST(e->flag, RELEASE_REQUEST)) {
	debug(20, 2, "storeCheckSwapable: NO: release requested\n");
    } else if (!storeEntryValidLength(e)) {
	debug(20, 2, "storeCheckSwapable: NO: wrong content-length\n");
    } else if (BIT_TEST(e->flag, ENTRY_NEGCACHED)) {
	debug(20, 2, "storeCheckSwapable: NO: negative cached\n");
	return 0;		/* avoid release call below */
    } else if (e->mem_obj->e_current_len > Config.Store.maxObjectSize) {
	debug(20, 2, "storeCheckSwapable: NO: too big\n");
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
    debug(20, 3, "storeComplete: '%s'\n", e->key);
    e->object_len = e->mem_obj->e_current_len;
    e->lastref = squid_curtime;
    e->store_status = STORE_OK;
    storeSetMemStatus(e, IN_MEMORY);
    e->swap_status = NO_SWAP;
    InvokeHandlers(e);
    safe_free(e->mem_obj->request_hdr);
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	storeRelease(e);
    else if (storeCheckSwapable(e))
	storeSwapOutStart(e);
    else {
	requestUnlink(e->mem_obj->request);
	e->mem_obj->request = NULL;
    }
}

/*
 * Fetch aborted.  Tell all clients to go home.  Negatively cache
 * abort message, freeing the data for this object 
 */
void
storeAbort(StoreEntry * e, const char *msg)
{
    LOCAL_ARRAY(char, mime_hdr, 300);
    char *abort_msg;
    MemObject *mem = e->mem_obj;

    if (e->store_status != STORE_PENDING) {
	debug_trap("storeAbort: bad store_status");
	return;
    } else if (mem == NULL) {
	debug_trap("storeAbort: null mem_obj");
	return;
    } else if (e->ping_status == PING_WAITING) {
	debug_trap("storeAbort: ping_status == PING_WAITING");
	return;
    }
    debug(20, 6, "storeAbort: '%s'\n", e->key);
    storeNegativeCache(e);
    e->store_status = STORE_ABORTED;
    storeSetMemStatus(e, IN_MEMORY);
    /* No DISK swap for negative cached object */
    e->swap_status = NO_SWAP;
    e->lastref = squid_curtime;
    /* In case some parent responds late and 
     * tries to restart the fetch, say that it's been
     * dispatched already.
     */
    BIT_SET(e->flag, ENTRY_DISPATCHED);
    storeLockObject(e);
    /* Count bytes faulted through cache but not moved to disk */
    HTTPCacheInfo->proto_touchobject(HTTPCacheInfo,
	mem->request ? mem->request->protocol : PROTO_NONE,
	mem->e_current_len);
    if (msg) {
	abort_msg = get_free_8k_page();
	strcpy(abort_msg, "HTTP/1.0 400 Cache Detected Error\r\n");
	mk_mime_hdr(mime_hdr,
	    "text/html",
	    strlen(msg),
	    (time_t) Config.negativeTtl,
	    squid_curtime);
	strcat(abort_msg, mime_hdr);
	strcat(abort_msg, "\r\n");
	strncat(abort_msg, msg, 8191 - strlen(abort_msg));
	storeAppend(e, abort_msg, strlen(abort_msg));
	safe_free(mem->e_abort_msg);
	mem->e_abort_msg = xstrdup(abort_msg);
	/* Set up object for negative caching */
	BIT_SET(e->flag, ABORT_MSG_PENDING);
	put_free_8k_page(abort_msg);
    }
    /* We assign an object length here--The only other place we assign the
     * object length is in storeComplete() */
    e->object_len = mem->e_current_len;
    InvokeHandlers(e);
    storeUnlockObject(e);
    return;
}

/* get the first in memory object entry in the storage */
static StoreEntry *
storeGetInMemFirst(void)
{
    hash_link *first = NULL;
    first = hash_first(in_mem_table);
    return (first ? ((StoreEntry *) first->item) : NULL);
}


/* get the next in memory object entry in the storage for a given
 * search pointer */
static StoreEntry *
storeGetInMemNext(void)
{
    hash_link *next = NULL;
    next = hash_next(in_mem_table);
    return (next ? ((StoreEntry *) next->item) : NULL);
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

/* free up all ttl-expired objects */
void
storePurgeOld(void *unused)
{
    StoreEntry *e = NULL;
    int n = 0;
    int count = 0;
    /* reschedule */
    eventAdd("storePurgeOld", storePurgeOld, NULL, Config.cleanRate);
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if ((++n & 0xFF) == 0) {
	    getCurrentTime();
	    if (shutdown_pending || reconfigure_pending)
		break;
	}
	if ((n & 0xFFF) == 0)
	    debug(20, 2, "storeWalkThrough: %7d objects so far.\n", n);
	if (storeCheckExpired(e, 1))
	    count += storeRelease(e);
    }
    debug(20, 0, "storePurgeOld: Removed %d objects\n", count);
}


/* Clear Memory storage to accommodate the given object len */
static void
storeGetMemSpace(int size)
{
    StoreEntry *e = NULL;
    StoreEntry **list = NULL;
    int list_count = 0;
    int n_expired = 0;
    int n_purged = 0;
    int n_released = 0;
    int n_locked = 0;
    int i;
    static time_t last_warning = 0;
    static time_t last_check = 0;
    int pages_needed;

    if (squid_curtime == last_check)
	return;
    last_check = squid_curtime;
    pages_needed = (size / SM_PAGE_SIZE) + 1;
    if (sm_stats.n_pages_in_use + pages_needed < store_pages_high)
	return;
    if (store_rebuilding)
	return;
    debug(20, 2, "storeGetMemSpace: Starting, need %d pages\n", pages_needed);

    list = xcalloc(meta_data.mem_obj_count, sizeof(ipcache_entry *));
    for (e = storeGetInMemFirst(); e; e = storeGetInMemNext()) {
	if (list_count == meta_data.mem_obj_count)
	    break;
	if (storeEntryLocked(e))
	    continue;
	if (storeCheckExpired(e, 0)) {
	    debug(20, 2, "storeGetMemSpace: Expired: %s\n", e->url);
	    n_expired++;
	    storeRelease(e);
	} else if (storeCheckPurgeMem(e)) {
	    debug(20, 3, "storeGetMemSpace: Adding '%s'\n", e->url);
	    *(list + list_count) = e;
	    list_count++;
	} else if (!storeEntryLocked(e)) {
	    debug(20, 3, "storeGetMemSpace: Adding '%s'\n", e->url);
	    *(list + list_count) = e;
	    list_count++;
	} else {
	    n_locked++;
	}
    }
    debug(20, 5, "storeGetMemSpace: Sorting LRU_list: %7d items\n", list_count);
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
	    debug_trap("storeGetMemSpace: Bad Entry in LRU list");
	}
    }

    i = 3;
    if (sm_stats.n_pages_in_use > store_pages_max) {
	if (squid_curtime - last_warning > 600) {
	    debug(20, 0, "WARNING: Exceeded 'cache_mem' size (%dK > %dK)\n",
		sm_stats.n_pages_in_use * 4, store_pages_max * 4);
	    last_warning = squid_curtime;
	    debug(20, 0, "Perhaps you should increase cache_mem?\n");
	    i = 0;
	}
    }
    debug(20, i, "storeGetMemSpace stats:\n");
    debug(20, i, "  %6d objects locked in memory\n", n_locked);
    debug(20, i, "  %6d LRU candidates\n", list_count);
    debug(20, i, "  %6d were purged\n", n_purged);
    debug(20, i, "  %6d were released\n", n_released);
    xfree(list);
}

static int
compareSize(StoreEntry ** e1, StoreEntry ** e2)
{
    if (!e1 || !e2)
	fatal_dump(NULL);
    if ((*e1)->mem_obj->e_current_len > (*e2)->mem_obj->e_current_len)
	return (1);
    if ((*e1)->mem_obj->e_current_len < (*e2)->mem_obj->e_current_len)
	return (-1);
    return (0);
}

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
    debug(20, 2, "storeGetSwapSpace: Starting...\n");

    /* Set flag if swap size over high-water-mark */
    if (store_swap_size + kb_size > store_swap_high)
	fReduceSwap = 1;

    debug(20, 2, "storeGetSwapSpace: Need %d bytes...\n", size);

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
		debug(20, 3, "storeGetSwapSpace: Expired '%s'\n", e->url);
		storeRelease(e);
	    } else if (!storeEntryLocked(e)) {
		*(LRU_list + list_count) = e;
		list_count++;
		scan_count++;
	    } else {
		locked++;
		locked_size += e->mem_obj->e_current_len;
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
    debug(20, 2, "storeGetSwapSpace: Current Size:   %7d kbytes\n",
	store_swap_size);
    debug(20, 2, "storeGetSwapSpace: High W Mark:    %7d kbytes\n",
	store_swap_high);
    debug(20, 2, "storeGetSwapSpace: Low W Mark:     %7d kbytes\n",
	store_swap_low);
    debug(20, 2, "storeGetSwapSpace: Entry count:    %7d items\n",
	meta_data.store_entries);
    debug(20, 2, "storeGetSwapSpace: Visited:        %7d buckets\n",
	i + 1);
    debug(20, 2, "storeGetSwapSpace: Scanned:        %7d items\n",
	scanned);
    debug(20, 2, "storeGetSwapSpace: Expired:        %7d items\n",
	expired);
    debug(20, 2, "storeGetSwapSpace: Locked:         %7d items\n",
	locked);
    debug(20, 2, "storeGetSwapSpace: Locked Space:   %7d bytes\n",
	locked_size);
    debug(20, 2, "storeGetSwapSpace: Scan in array:  %7d bytes\n",
	scan_in_objs);
    debug(20, 2, "storeGetSwapSpace: LRU candidate:  %7d items\n",
	LRU_list->index);
#endif /* LOTSA_DEBUGGING */

    for (i = 0; i < list_count; i++)
	removed += storeRelease(*(LRU_list + i));
    if (store_swap_size + kb_size <= store_swap_low)
	fReduceSwap = 0;
    debug(20, 2, "storeGetSwapSpace: After Freeing Size:   %7d kbytes\n",
	store_swap_size);
    /* free the list */
    safe_free(LRU_list);

    if ((store_swap_size + kb_size > store_swap_high)) {
	i = 2;
	if (++swap_help > SWAP_MAX_HELP) {
	    debug(20, 0, "WARNING: Repeated failures to free up disk space!\n");
	    i = 0;
	}
	debug(20, i, "storeGetSwapSpace: Disk usage is over high water mark\n");
	debug(20, i, "--> store_swap_high = %d KB\n", store_swap_high);
	debug(20, i, "--> store_swap_size = %d KB\n", store_swap_size);
	debug(20, i, "--> asking for        %d KB\n", kb_size);
    } else {
	swap_help = 0;
    }

    getCurrentTime();		/* we may have taken more than one second */
    debug(20, 2, "Removed %d objects\n", removed);
    return 0;
}


/* release an object from a cache */
/* return number of objects released. */
int
storeRelease(StoreEntry * e)
{
    StoreEntry *hentry = NULL;
    const char *hkey;
    debug(20, 3, "storeRelease: Releasing: '%s'\n", e->key);
    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */
    if (storeEntryLocked(e)) {
	storeExpireNow(e);
	debug(20, 3, "storeRelease: Only setting RELEASE_REQUEST bit\n");
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
	debug(20, 2, "storeRelease: Delaying release until store is rebuilt: '%s'\n",
	    e->key ? e->key : e->url ? e->url : "NO URL");
	storeExpireNow(e);
	storeSetPrivateKey(e);
	return 0;
    }
    if (e->swap_status == SWAP_OK && (e->swap_file_number > -1)) {
	if (BIT_TEST(e->flag, ENTRY_VALIDATED))
	    storePutUnusedFileno(e->swap_file_number);
	storeDirUpdateSwapSize(e->swap_file_number, e->object_len, -1);
	e->swap_file_number = -1;
	HTTPCacheInfo->proto_purgeobject(HTTPCacheInfo,
	    urlParseProtocol(e->url),
	    e->object_len);
    }
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
    if (e->swap_status == SWAPPING_OUT)
	return 1;
    if (e->mem_status == SWAPPING_IN)
	return 1;
    if (e->store_status == STORE_PENDING)
	return 1;
    return 0;
}

static int
storeCopy(const StoreEntry * e, int stateoffset, int maxSize, char *buf, int *size)
{
    MemObject *mem = e->mem_obj;
    size_t s;
    assert(stateoffset >= mem->e_lowest_offset);
    s = memCopy(mem->data, stateoffset, buf, maxSize);
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

static int
storeClientListSearch(const MemObject * mem, void *data)
{
    int i;
    if (mem->clients) {
	for (i = 0; i < mem->nclients; i++) {
	    if (mem->clients[i].callback_data != data)
		continue;
	    return i;
	}
    }
    return -1;
}

/* add client with fd to client list */
int
storeClientListAdd(StoreEntry * e, void *data)
{
    int i;
    MemObject *mem = e->mem_obj;
    struct _store_client *oldlist = NULL;
    int oldsize;
    assert(mem != NULL);
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
	debug(20, 3, "storeClientListAdd: Growing clients for '%s'\n", e->url);
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
    int ci;
    size_t sz;
    MemObject *mem = e->mem_obj;
    struct _store_client *sc;
    static int recurse_detect = 0;
    assert(seen_offset <= mem->e_current_len);
    assert(copy_offset >= mem->e_lowest_offset);
    assert(recurse_detect == 0);
    if ((ci = storeClientListSearch(mem, data)) < 0)
	fatal_dump("storeClientCopy: Unregistered client");
    sc = &mem->clients[ci];
    sc->copy_offset = copy_offset;
    sc->seen_offset = seen_offset;
    if (seen_offset == mem->e_current_len) {
	/* client has already seen this, wait for more */
	sc->callback = callback;
	sc->copy_buf = buf;
	sc->copy_size = size;
	sc->copy_offset = copy_offset;
	return;
    }
    sz = memCopy(mem->data, copy_offset, buf, size);
    recurse_detect = 1;
    callback(data, buf, sz);
    recurse_detect = 0;
    /* see if we can get rid of some data if we are in "delete behind" mode . */
    if (BIT_TEST(e->flag, DELETE_BEHIND))
	storeDeleteBehind(e);
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

    debug(20, 3, "storeEntryValidLength: Checking '%s'\n", e->key);
    debug(20, 5, "storeEntryValidLength:     object_len = %d\n", e->object_len);
    debug(20, 5, "storeEntryValidLength:         hdr_sz = %d\n", hdr_sz);
    debug(20, 5, "storeEntryValidLength: content_length = %d\n", content_length);

    if (content_length == 0) {
	debug(20, 5, "storeEntryValidLength: Zero content length; assume valid; '%s'\n",
	    e->key);
	return 1;
    }
    if (hdr_sz == 0) {
	debug(20, 5, "storeEntryValidLength: Zero header size; assume valid; '%s'\n",
	    e->key);
	return 1;
    }
    diff = hdr_sz + content_length - e->object_len;
    if (diff != 0) {
	debug(20, 3, "storeEntryValidLength: %d bytes too %s; '%s'\n",
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
    debug(20, 1, "Swap maxSize %d kB, estimated %d objects\n",
	Config.Swap.maxSize, i);
    i /= Config.Store.objectsPerBucket;
    debug(20, 1, "Target number of buckets: %d\n", i);
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
    debug(20, 1, "Using %d Store buckets, maintain %d bucket%s every %d second%s\n",
	store_buckets,
	store_maintain_buckets,
	store_maintain_buckets == 1 ? null_string : "s",
	store_maintain_rate,
	store_maintain_rate == 1 ? null_string : "s");
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
	debug(20, 1, "Store logging disabled\n");
    if (ncache_dirs < 1)
	fatal("No cache_dir's specified in config file");
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
		debug(51, 1, "Completed %d full expiration scans of store table\n",
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
    debug(51, rm_obj ? 2 : 9, "Removed %d of %d objects from bucket %d\n",
	rm_obj, scan_obj, (int) b->bucket);
    /* Don't remove stuff if we're still validating - we could remove good
     * stuff when we don't want to */
    if (store_validating)
	return;
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
storeWriteCleanLogs(void)
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
	debug(20, 1, "Not currently OK to rewrite swap log.\n");
	debug(20, 1, "storeWriteCleanLogs: Operation aborted.\n");
	return 0;
    }
    debug(20, 1, "storeWriteCleanLogs: Starting...\n");
    start = getCurrentTime();
    fd = xcalloc(ncache_dirs, sizeof(int));
    cur = xcalloc(ncache_dirs, sizeof(char *));
    new = xcalloc(ncache_dirs, sizeof(char *));
    cln = xcalloc(ncache_dirs, sizeof(char *));
    for (dirn = 0; dirn < ncache_dirs; dirn++) {
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
	    debug(50, 0, "storeWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
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
	if (e->swap_status != SWAP_OK)
	    continue;
	if (e->object_len <= 0)
	    continue;
	if (BIT_TEST(e->flag, RELEASE_REQUEST))
	    continue;
	if (BIT_TEST(e->flag, KEY_PRIVATE))
	    continue;
	if ((dirn = storeDirNumber(e->swap_file_number)) >= ncache_dirs) {
	    debug_trap("storeWriteCleanLogss: dirn out of range");
	    continue;
	}
	if (fd[dirn] < 0)
	    continue;
	sprintf(line, "%08x %08x %08x %08x %9d %s\n",
	    (int) e->swap_file_number,
	    (int) e->timestamp,
	    (int) e->expires,
	    (int) e->lastmod,
	    e->object_len,
	    e->url);
	if (write(fd[dirn], line, strlen(line)) < 0) {
	    debug(50, 0, "storeWriteCleanLogs: %s: %s\n", new[dirn], xstrerror());
	    debug(20, 0, "storeWriteCleanLogs: Current swap logfile not replaced.\n");
	    file_close(fd[dirn]);
	    fd[dirn] = -1;
	    safeunlink(cln[dirn], 0);
	    continue;
	}
	if ((++n & 0x3FFF) == 0) {
	    getCurrentTime();
	    debug(20, 1, "  %7d lines written so far.\n", n);
	}
    }
    safe_free(line);
    for (dirn = 0; dirn < ncache_dirs; dirn++) {
	file_close(fd[dirn]);
	fd[dirn] = -1;
	if (rename(new[dirn], cur[dirn]) < 0) {
	    debug(50, 0, "storeWriteCleanLogs: rename failed: %s\n",
		xstrerror());
	}
    }
    storeDirCloseSwapLogs();
    storeDirOpenSwapLogs();
    stop = getCurrentTime();
    r = stop - start;
    debug(20, 1, "  Finished.  Wrote %d lines.\n", n);
    debug(20, 1, "  Took %d seconds (%6.1lf lines/sec).\n",
	r > 0 ? r : 0, (double) n / (r > 0 ? r : 1));
    /* touch a timestamp file if we're not still validating */
    for (dirn = 0; dirn < ncache_dirs; dirn++) {
	if (!store_validating)
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

static int
swapInError(int fd_unused, StoreEntry * entry)
{
    squid_error_entry(entry, ERR_DISK_IO, xstrerror());
    return 0;
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
    struct stat sb;

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

    debug(20, 1, "storeRotateLog: Rotating.\n");

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	sprintf(from, "%s.%d", fname, i - 1);
	sprintf(to, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	sprintf(to, "%s.%d", fname, 0);
	rename(fname, to);
    }
    storelog_fd = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL);
    if (storelog_fd < 0) {
	debug(50, 0, "storeRotateLog: %s: %s\n", fname, xstrerror());
	debug(20, 1, "Store logging disabled\n");
    }
}

static int
storeShouldPurgeMem(const StoreEntry * e)
{
    if (storeCheckPurgeMem(e) == 0)
	return 0;
    if (sm_stats.n_pages_in_use > store_pages_low)
	return 1;
    return 0;
}


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
    if (e->swap_status != SWAP_OK)
	return 0;
    return 1;
}

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
    safe_free(MaintBucketsOrder);
    storeDirCloseSwapLogs();
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
int fileno_stack_count = 0;

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
    if (!storeDirMapBitTest(fileno))
	fatal_dump("storePutUnusedFileno: fileno not in use");
    storeDirMapBitReset(fileno);
    if (fileno_stack_count < FILENO_STACK_SIZE)
	fileno_stack[fileno_stack_count++] = fileno;
    else
	unlinkdUnlink(storeSwapFullPath(fileno, NULL));
}
