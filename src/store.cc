
/*
 * $Id: store.cc,v 1.158 1996/11/08 00:02:24 wessels Exp $
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

#define REBUILD_TIMESTAMP_DELTA_MAX 2
#define MAX_SWAP_FILE		(1<<21)
#define SWAP_BUF		DISK_PAGE_SIZE

#define WITH_MEMOBJ	1
#define WITHOUT_MEMOBJ	0

#define STORE_IN_MEM_BUCKETS		(143)

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
    "PING_WAITING",
    "PING_TIMEOUT",
    "PING_DONE",
    "PING_NONE"
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

struct storeRebuild_data {
    FILE *log;
    int objcount;		/* # objects successfully reloaded */
    int expcount;		/* # objects expired */
    int linecount;		/* # lines parsed from cache logfile */
    int clashcount;		/* # swapfile clashes avoided */
    int dupcount;		/* # duplicates purged */
    time_t start, stop;
    int speed;			/* # Objects per run */
    char line_in[4096];
};

/* initializtion flag */
int store_rebuilding = STORE_REBUILDING_SLOW;

/* Static Functions */
static const char *storeDescribeStatus _PARAMS((const StoreEntry *));
static char *storeSwapFullPath _PARAMS((int, char *));
static HashID storeCreateHashTable _PARAMS((int (*)_PARAMS((const char *, const char *))));
static int compareLastRef _PARAMS((StoreEntry **, StoreEntry **));
static int compareSize _PARAMS((StoreEntry **, StoreEntry **));
static int storeAddSwapDisk _PARAMS((const char *));
static int storeCheckExpired _PARAMS((const StoreEntry *));
static int storeCheckPurgeMem _PARAMS((const StoreEntry *));
static int storeClientListSearch _PARAMS((const MemObject *, int));
static int storeCopy _PARAMS((const StoreEntry *, int, int, char *, int *));
static int storeEntryLocked _PARAMS((const StoreEntry *));
static int storeEntryValidLength _PARAMS((const StoreEntry *));
static void storeGetMemSpace _PARAMS((int));
static int storeHashDelete _PARAMS((StoreEntry *));
static int storeShouldPurgeMem _PARAMS((const StoreEntry *));
static int storeSwapInHandle _PARAMS((int, const char *, int, int, StoreEntry *, int));
static int storeSwapInStart _PARAMS((StoreEntry *, SIH, void *));
static int swapInError _PARAMS((int, StoreEntry *));
static mem_ptr new_MemObjectData _PARAMS((void));
static MemObject *new_MemObject _PARAMS((void));
static StoreEntry *new_StoreEntry _PARAMS((int));
static StoreEntry *storeAddDiskRestore _PARAMS((const char *, int, int, time_t, time_t, time_t));
static StoreEntry *storeGetInMemFirst _PARAMS((void));
static StoreEntry *storeGetInMemNext _PARAMS((void));
static unsigned int storeGetBucketNum _PARAMS((void));
static void destroy_MemObject _PARAMS((MemObject *));
static void destroy_MemObjectData _PARAMS((MemObject *));
static void destroy_StoreEntry _PARAMS((StoreEntry *));
static void storeDeleteBehind _PARAMS((StoreEntry *));
static void storePurgeMem _PARAMS((StoreEntry *));
static void storeSanityCheck _PARAMS((void));
static void storeSetMemStatus _PARAMS((StoreEntry *, mem_status_t));
static void storeStartRebuildFromDisk _PARAMS((void));
static void storeSwapLog _PARAMS((const StoreEntry *));
static void storeSwapOutHandle _PARAMS((int, int, StoreEntry *));
static void storeHashMemInsert _PARAMS((StoreEntry *));
static void storeHashMemDelete _PARAMS((StoreEntry *));
static void storeSetPrivateKey _PARAMS((StoreEntry *));

/* Now, this table is inaccessible to outsider. They have to use a method
 * to access a value in internal storage data structure. */
static HashID store_table = 0;
/* hash table for in-memory-only objects */
static HashID in_mem_table = 0;

/* current memory storage size */
unsigned long store_mem_size = 0;

static int store_pages_high = 0;
static int store_pages_low = 0;
static int store_pages_over_high = 0;

/* current file name, swap file, use number as a filename */
static int swapfileno = 0;
static int store_swap_size = 0;	/* kilobytes !! */
static unsigned long store_swap_high = 0;
static unsigned long store_swap_low = 0;
static int swaplog_fd = -1;
static int swaplog_lock = 0;
static int storelog_fd = -1;

/* key temp buffer */
static char key_temp_buffer[MAX_URL + 100];
static char swaplog_file[SQUID_MAXPATHLEN + 1];
static char tmp_filename[SQUID_MAXPATHLEN + 1];

/* patch cache_dir to accomodate multiple disk storage */
static char **CacheDirs = NULL;
static int CacheDirsAllocated = 0;
int ncache_dirs = 0;

/* expiration parameters and stats */
static int store_buckets;
int store_maintain_rate;
static int store_maintain_buckets;
int scan_revolutions;

static MemObject *
new_MemObject(void)
{
    MemObject *mem = get_free_mem_obj();
    mem->reply = xcalloc(1, sizeof(struct _http_reply));
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
    safe_free(mem->mime_hdr);
    safe_free(mem->reply);
    safe_free(mem->e_abort_msg);
    requestUnlink(mem->request);
    mem->request = NULL;
    memset(mem, '\0', sizeof(MemObject));
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
	debug(20, 3, "destroy_StoreEntry: WARNING!  Entry without URL string!\n");
    }
    if (BIT_TEST(e->flag, KEY_URL))
	e->key = NULL;
    else
	safe_free(e->key);
    memset(e, '\0', sizeof(StoreEntry));
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
	mem->data->mem_free(mem->data);
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

static char *
time_describe(time_t t)
{
    LOCAL_ARRAY(char, buf, 128);

    if (t < 60) {
	sprintf(buf, "%ds", (int) t);
    } else if (t < 3600) {
	sprintf(buf, "%dm", (int) t / 60);
    } else if (t < 86400) {
	sprintf(buf, "%dh", (int) t / 3600);
    } else if (t < 604800) {
	sprintf(buf, "%dD", (int) t / 86400);
    } else if (t < 2592000) {
	sprintf(buf, "%dW", (int) t / 604800);
    } else if (t < 31536000) {
	sprintf(buf, "%dM", (int) t / 2592000);
    } else {
	sprintf(buf, "%dY", (int) t / 31536000);
    }
    return buf;
}

static void
storeLog(int tag, const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    time_t t = -1;
    int expect_len = 0;
    int actual_len = 0;
    int code = 0;
    if (storelog_fd < 0)
	return;
    if (-1 < e->expires)
	t = e->expires - squid_curtime;
    if (e->mem_obj) {
	code = e->mem_obj->reply->code;
	expect_len = (int) e->mem_obj->reply->content_length;
	actual_len = (int) e->mem_obj->e_current_len - e->mem_obj->reply->hdr_sz;
    }
    sprintf(logmsg, "%9d.%03d %-7s %4d %9d [%3s] %d/%d %s\n",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec / 1000,
	storeLogTags[tag],
	code,
	(int) t,
	time_describe(t),
	expect_len,
	actual_len,
	e->key);
    file_write(storelog_fd,
	xstrdup(logmsg),
	strlen(logmsg),
	0,
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

/* lock the object for reading, start swapping in if necessary */
/* Called by:
 * icpProcessRequest()
 * storeAbort()
 * {http,ftp,gopher,wais}Start()
 */
int
storeLockObject(StoreEntry * e, SIH handler, void *data)
{
    int status = 0;
    e->lock_count++;
    debug(20, 3, "storeLockObject: key '%s' count=%d\n",
	e->key, (int) e->lock_count);
    if (e->mem_status != NOT_IN_MEMORY)
	/* ok, its either IN_MEMORY or SWAPPING_IN */
	debug(20, 5, "storeLockObject: OK: mem_status is %s\n", memStatusStr[e->mem_status]);
    else if (e->swap_status == SWAP_OK)
	/* ok, its NOT_IN_MEMORY, but its swapped out */
	debug(20, 5, "storeLockObject: OK: swap_status is %s\n", swapStatusStr[e->swap_status]);
    else if (e->store_status == STORE_PENDING)
	/* ok, we're reading it in right now */
	debug(20, 5, "storeLockObject: OK: store_status is %s\n", storeStatusStr[e->store_status]);
    else
	fatal_dump(storeDescribeStatus(e));
    e->lastref = squid_curtime;
    /* If the object is NOT_IN_MEMORY, fault it in. */
    if ((e->mem_status == NOT_IN_MEMORY) && (e->swap_status == SWAP_OK)) {
	/* object is in disk and no swapping daemon running. Bring it in. */
	if ((status = storeSwapInStart(e, handler, data)) < 0) {
	    /* We couldn't find or couldn't open object's swapfile.
	     * So, return a -1 here, indicating that we will treat
	     * the reference like a MISS_TTL, force a keychange and
	     storeRelease.  */
	    e->lock_count--;
	}
    } else if (e->mem_status == IN_MEMORY && handler) {
	/* its already in memory, so call the handler */
	handler(0, data);
    } else if (handler) {
	/* The object is probably in state SWAPPING_IN, not much we can do.
	 * Instead of returning failure here, we should have a list of complete
	 * handlers which we could append to... */
	handler(1, data);
    }
    return status;
}

void
storeReleaseRequest(StoreEntry * e)
{
    if (BIT_TEST(e->flag, RELEASE_REQUEST))
	return;
    if (!storeEntryLocked(e)) {
	debug_trap("Someone called storeReleaseRequest on an unlocked entry");
	debug(20, 0, "  --> '%s'\n", e->url ? e->url : "NULL URL");
	return;
    }
    debug(20, 3, "storeReleaseRequest: FOR '%s'\n", e->key ? e->key : e->url);
    e->flag |= RELEASE_REQUEST;
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
	debug_trap("storeUnlockObject: Someone unlocked STORE_PENDING object");
	e->store_status = STORE_ABORTED;
    }
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
    if (++key_counter == 0)
	++key_counter;
    return key_counter;
}

const char *
storeGeneratePrivateKey(const char *url, method_t method, int num)
{
    if (num == 0)
	num = getKeyCounter();
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
	sprintf(key_temp_buffer, "/post/%s", url);
	return key_temp_buffer;
	/* NOTREACHED */
	break;
    case METHOD_PUT:
	sprintf(key_temp_buffer, "/put/%s", url);
	return key_temp_buffer;
	/* NOTREACHED */
	break;
    case METHOD_HEAD:
	sprintf(key_temp_buffer, "/head/%s", url);
	return key_temp_buffer;
	/* NOTREACHED */
	break;
    case METHOD_CONNECT:
	sprintf(key_temp_buffer, "/connect/%s", url);
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
    StoreEntry *e2 = NULL;
    hash_link *table_entry = NULL;
    const char *newkey = NULL;

    if (e->key && BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already private */

    newkey = storeGeneratePrivateKey(e->url, e->method, 0);
    if ((table_entry = hash_lookup(store_table, newkey))) {
	e2 = (StoreEntry *) table_entry;
	debug(20, 0, "storeSetPrivateKey: Entry already exists with key '%s'\n",
	    newkey);
	debug(20, 0, "storeSetPrivateKey: Entry Dump:\n%s\n", storeToString(e2));
	debug_trap("Private key already exists.");
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
    int i;
    debug(20, 3, "storeCreateEntry: '%s' icp flags=%x\n", url, flags);

    e = new_StoreEntry(WITH_MEMOBJ);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    e->url = xstrdup(url);
    meta_data.url_strings += strlen(url);
    e->method = method;
    if (req_hdr) {
	mem->mime_hdr_sz = req_hdr_sz;
	mem->mime_hdr = xmalloc(req_hdr_sz + 1);
	xmemcpy(mem->mime_hdr, req_hdr, req_hdr_sz);
	*(mem->mime_hdr + req_hdr_sz) = '\0';
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
    e->timestamp = 0;		/* set in timestampsSet() */
    e->ping_status = PING_NONE;

    /* allocate client list */
    mem->nclients = MIN_CLIENT;
    mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
    for (i = 0; i < mem->nclients; i++)
	mem->clients[i].fd = -1;
    /* storeLog(STORE_LOG_CREATE, e); */
    return e;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
static StoreEntry *
storeAddDiskRestore(const char *url, int file_number, int size, time_t expires, time_t timestamp, time_t lastmod)
{
    StoreEntry *e = NULL;

    debug(20, 5, "StoreAddDiskRestore: '%s': size %d: expires %d: file_number %d\n",
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
    file_map_bit_set(file_number);
    e->object_len = size;
    e->lock_count = 0;
    BIT_RESET(e->flag, CLIENT_ABORT_REQUEST);
    e->refcount = 0;
    e->lastref = timestamp;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->ping_status = PING_NONE;
    return e;
}

/* Register interest in an object currently being retrieved. */
int
storeRegister(StoreEntry * e, int fd, PIF handler, void *data)
{
    int i;
    MemObject *mem = e->mem_obj;
    debug(20, 3, "storeRegister: FD %d '%s'\n", fd, e->key);
    if ((i = storeClientListSearch(mem, fd)) < 0)
	i = storeClientListAdd(e, fd, 0);
    if (mem->clients[i].callback)
	fatal_dump("storeRegister: handler already exists");
    mem->clients[i].callback = handler;
    mem->clients[i].callback_data = data;
    return 0;
}

int
storeUnregister(StoreEntry * e, int fd)
{
    int i;
    MemObject *mem = e->mem_obj;
    if (mem == NULL)
	return 0;
    debug(20, 3, "storeUnregister: called for FD %d '%s'\n", fd, e->key);
    if ((i = storeClientListSearch(mem, fd)) < 0)
	return 0;
    mem->clients[i].fd = -1;
    mem->clients[i].last_offset = 0;
    mem->clients[i].callback = NULL;
    mem->clients[i].callback_data = NULL;
    if (mem->fd_of_first_client == fd)
	mem->fd_of_first_client = -1;
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
	if (mem->clients[i].fd == -1)
	    continue;
	if (mem->clients[i].last_offset < lowest)
	    lowest = mem->clients[i].last_offset;
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
    new_lowest_offset = (int) mem->data->mem_free_data_upto(mem->data,
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
    PIF handler = NULL;
    void *data = NULL;
    struct _store_client *sc;
    /* walk the entire list looking for valid handlers */
    for (i = 0; i < mem->nclients; i++) {
	sc = &mem->clients[i];
	if (sc->fd == -1)
	    continue;
	if ((handler = sc->callback) == NULL)
	    continue;
	data = sc->callback_data;
	sc->callback = NULL;
	sc->callback_data = NULL;
	handler(sc->fd, e, data);
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
    debug(20, 1, "storeStartDeleteBehind: '%s' at %d bytes\n", e->url,
	e->mem_obj->e_current_len);
    storeSetPrivateKey(e);
    BIT_SET(e->flag, DELETE_BEHIND);
    storeReleaseRequest(e);
    BIT_RESET(e->flag, ENTRY_CACHABLE);
    storeExpireNow(e);
}

/* Append incoming data from a primary server to an entry. */
void
storeAppend(StoreEntry * e, const char *data, int len)
{
    MemObject *mem;
    /* sanity check */
    if (e == NULL) {
	debug_trap("storeAppend: NULL entry.");
	return;
    } else if ((mem = e->mem_obj) == NULL) {
	debug_trap("storeAppend: NULL entry->mem_obj");
	return;
    } else if (mem->data == NULL) {
	debug_trap("storeAppend: NULL entry->mem_obj->data");
	return;
    }
    if (len) {
	debug(20, 5, "storeAppend: appending %d bytes for '%s'\n", len, e->key);
	storeGetMemSpace(len);
	if (store_pages_over_high) {
	    if (mem->e_current_len > Config.Store.maxObjectSize)
		storeStartDeleteBehind(e);
	}
	store_mem_size += len;
	(void) mem->data->mem_append(mem->data, data, len);
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

/* add directory to swap disk */
static int
storeAddSwapDisk(const char *path)
{
    char **tmp = NULL;
    int i;
    if (strlen(path) > (SQUID_MAXPATHLEN - 32))
	fatal_dump("cache_dir pathname is too long");
    if (CacheDirs == NULL) {
	CacheDirsAllocated = 4;
	CacheDirs = xcalloc(CacheDirsAllocated, sizeof(char *));
    }
    if (CacheDirsAllocated == ncache_dirs) {
	CacheDirsAllocated <<= 1;
	tmp = xcalloc(CacheDirsAllocated, sizeof(char *));
	for (i = 0; i < ncache_dirs; i++)
	    *(tmp + i) = *(CacheDirs + i);
	xfree(CacheDirs);
	CacheDirs = tmp;
    }
    *(CacheDirs + ncache_dirs) = xstrdup(path);
    return ++ncache_dirs;
}

/* return the nth swap directory */
const char *
swappath(int n)
{
    return *(CacheDirs + (n % ncache_dirs));
}


/* return full name to swapfile */
static char *
storeSwapFullPath(int fn, char *fullpath)
{
    LOCAL_ARRAY(char, fullfilename, SQUID_MAXPATHLEN + 1);
    if (!fullpath)
	fullpath = fullfilename;
    fullpath[0] = '\0';
    sprintf(fullpath, "%s/%02X/%02X/%08X",
	swappath(fn),
	(fn / ncache_dirs) % SWAP_DIRECTORIES_L1,
	(fn / ncache_dirs) / SWAP_DIRECTORIES_L1 % SWAP_DIRECTORIES_L2,
	fn);
    return fullpath;
}

/* swapping in handle */
static int
storeSwapInHandle(int fd_notused, const char *buf, int len, int flag, StoreEntry * e, int offset_notused)
{
    MemObject *mem = e->mem_obj;
    SIH handler = NULL;
    void *data = NULL;
    debug(20, 2, "storeSwapInHandle: '%s'\n", e->key);

    if ((flag < 0) && (flag != DISK_EOF)) {
	debug(20, 0, "storeSwapInHandle: SwapIn failure (err code = %d).\n", flag);
	put_free_8k_page(mem->e_swap_buf);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	file_close(mem->swapin_fd);
	swapInError(-1, e);	/* Invokes storeAbort() and completes the I/O */
	if ((handler = mem->swapin_complete_handler) != NULL) {
	    data = mem->swapin_complete_data;
	    mem->swapin_complete_handler = NULL;
	    mem->swapin_complete_data = NULL;
	    handler(2, data);
	}
	return -1;
    }
    debug(20, 5, "storeSwapInHandle: e->swap_offset   = %d\n", mem->swap_offset);
    debug(20, 5, "storeSwapInHandle: len              = %d\n", len);
    debug(20, 5, "storeSwapInHandle: e->e_current_len = %d\n", mem->e_current_len);
    debug(20, 5, "storeSwapInHandle: e->object_len    = %d\n", e->object_len);

    /* always call these, even if len == 0 */
    mem->swap_offset += len;
    storeAppend(e, buf, len);

    if (mem->e_current_len < e->object_len && flag != DISK_EOF) {
	/* some more data to swap in, reschedule */
	file_read(mem->swapin_fd,
	    mem->e_swap_buf,
	    SWAP_BUF,
	    mem->swap_offset,
	    (FILE_READ_HD) storeSwapInHandle,
	    (void *) e);
    } else {
	/* complete swapping in */
	storeSetMemStatus(e, IN_MEMORY);
	put_free_8k_page(mem->e_swap_buf);
	file_close(mem->swapin_fd);
	storeLog(STORE_LOG_SWAPIN, e);
	debug(20, 5, "storeSwapInHandle: SwapIn complete: '%s' from %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	if (mem->e_current_len != e->object_len) {
	    debug(20, 0, "storeSwapInHandle: WARNING! Object size mismatch.\n");
	    debug(20, 0, "  --> '%s'\n", e->url);
	    debug(20, 0, "  --> Expecting %d bytes from file: %s\n", e->object_len,
		storeSwapFullPath(e->swap_file_number, NULL));
	    debug(20, 0, "  --> Only read %d bytes\n",
		mem->e_current_len);
	}
	if ((handler = mem->swapin_complete_handler) != NULL) {
	    data = mem->swapin_complete_data;
	    mem->swapin_complete_handler = NULL;
	    mem->swapin_complete_data = NULL;
	    handler(0, data);
	}
	if (BIT_TEST(e->flag, RELEASE_REQUEST)) {
	    storeRelease(e);
	} else if ((mem = e->mem_obj)) {
	    requestUnlink(mem->request);
	    mem->request = NULL;
	}
    }
    return 0;
}

/* start swapping in */
static int
storeSwapInStart(StoreEntry * e, SIH swapin_complete_handler, void *swapin_complete_data)
{
    int fd;
    char *path = NULL;
    MemObject *mem = NULL;

    /* sanity check! */
    if (e->swap_status != SWAP_OK) {
	debug_trap("storeSwapInStart: bad swap_status");
	return -1;
    } else if (e->swap_file_number < 0) {
	debug_trap("storeSwapInStart: bad swap_file_number");
	return -1;
    } else if (e->mem_obj) {
	debug_trap("storeSwapInStart: mem_obj already present");
	return -1;
    }
    e->mem_obj = mem = new_MemObject();

    path = storeSwapFullPath(e->swap_file_number, NULL);
    if ((fd = file_open(path, NULL, O_RDONLY)) < 0) {
	debug(20, 0, "storeSwapInStart: Failed for '%s'\n", e->url);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	/* Invoke a store abort that should free the memory object */
	return -1;
    }
    mem->swapin_fd = (short) fd;
    debug(20, 5, "storeSwapInStart: initialized swap file '%s' for '%s'\n",
	path, e->url);
    storeSetMemStatus(e, SWAPPING_IN);
    mem->data = new_MemObjectData();
    mem->swap_offset = 0;
    mem->e_swap_buf = get_free_8k_page();

    /* start swapping daemon */
    file_read(fd,
	mem->e_swap_buf,
	SWAP_BUF,
	mem->swap_offset,
	(FILE_READ_HD) storeSwapInHandle,
	(void *) e);
    mem->swapin_complete_handler = swapin_complete_handler;
    mem->swapin_complete_data = swapin_complete_data;
    return 0;
}

static void
storeSwapLog(const StoreEntry * e)
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    /* Note this printf format appears in storeWriteCleanLog() too */
    sprintf(logmsg, "%08x %08x %08x %08x %9d %s\n",
	(int) e->swap_file_number,
	(int) e->timestamp,
	(int) e->expires,
	(int) e->lastmod,
	e->object_len,
	e->url);
    file_write(swaplog_fd,
	xstrdup(logmsg),
	strlen(logmsg),
	swaplog_lock,
	NULL,
	NULL,
	xfree);
}

static void
storeSwapOutHandle(int fd, int flag, StoreEntry * e)
{
    LOCAL_ARRAY(char, filename, SQUID_MAXPATHLEN + 1);
    MemObject *mem = e->mem_obj;

    debug(20, 3, "storeSwapOutHandle: '%s'\n", e->key);
    if (mem == NULL) {
	debug(20, 0, "%s\n", storeToString(e));
	debug_trap("Someone is swapping out a bad entry");
	return;
    }
    storeSwapFullPath(e->swap_file_number, filename);

    if (flag < 0) {
	debug(20, 1, "storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = NO_SWAP;
	put_free_8k_page(mem->e_swap_buf);
	file_close(fd);
	storeRelease(e);
	if (e->swap_file_number != -1) {
	    file_map_bit_reset(e->swap_file_number);
	    safeunlink(filename, 0);	/* remove it */
	    e->swap_file_number = -1;
	}
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
    store_swap_size += ((mem->e_swap_buf_len + 1023) >> 10);
    if (mem->swap_offset >= e->object_len) {
	/* swapping complete */
	e->swap_status = SWAP_OK;
	file_close(mem->swapout_fd);
	storeLog(STORE_LOG_SWAPOUT, e);
	debug(20, 5, "storeSwapOutHandle: SwapOut complete: '%s' to %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	put_free_8k_page(mem->e_swap_buf);
	storeSwapLog(e);
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
    storeCopy(e,
	mem->swap_offset,
	SWAP_BUF,
	mem->e_swap_buf,
	&(mem->e_swap_buf_len));
    file_write(mem->swapout_fd,
	mem->e_swap_buf,
	mem->e_swap_buf_len,
	mem->e_swap_access,
	storeSwapOutHandle,
	e,
	NULL);
    return;
}


/* start swapping object to disk */
static int
storeSwapOutStart(StoreEntry * e)
{
    int fd;
    int x;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN + 1);
    MemObject *mem = e->mem_obj;
    /* Suggest a new swap file number */
    swapfileno = (swapfileno + 1) % (MAX_SWAP_FILE);
    /* Record the number returned */
    swapfileno = file_map_allocate(swapfileno);
    storeSwapFullPath(swapfileno, swapfilename);
    fd = file_open(swapfilename, NULL, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) {
	debug(20, 0, "storeSwapOutStart: Unable to open swapfile: %s\n",
	    swapfilename);
	file_map_bit_reset(swapfileno);
	e->swap_file_number = -1;
	return -1;
    }
    mem->swapout_fd = (short) fd;
    debug(20, 5, "storeSwapOutStart: Begin SwapOut '%s' to FD %d FILE %s.\n",
	e->url, fd, swapfilename);
    e->swap_file_number = swapfileno;
    if ((mem->e_swap_access = file_write_lock(mem->swapout_fd)) < 0) {
	debug(20, 0, "storeSwapOutStart: Unable to lock swapfile: %s\n",
	    swapfilename);
	file_map_bit_reset(e->swap_file_number);
	e->swap_file_number = -1;
	return -1;
    }
    e->swap_status = SWAPPING_OUT;
    mem->swap_offset = 0;
    mem->e_swap_buf = get_free_8k_page();
    mem->e_swap_buf_len = 0;
    storeCopy(e,
	0,
	SWAP_BUF,
	mem->e_swap_buf,
	&mem->e_swap_buf_len);
    /* start swapping daemon */
    x = file_write(mem->swapout_fd,
	mem->e_swap_buf,
	mem->e_swap_buf_len,
	mem->e_swap_access,
	storeSwapOutHandle,
	e,
	NULL);
    if (x != DISK_OK)
	fatal_dump(NULL);	/* This shouldn't happen */
    return 0;
}

/* recreate meta data from disk image in swap directory */

/* Add one swap file at a time from disk storage */
static int
storeDoRebuildFromDisk(struct storeRebuild_data *data)
{
    LOCAL_ARRAY(char, swapfile, MAXPATHLEN);
    LOCAL_ARRAY(char, url, MAX_URL + 1);
    StoreEntry *e = NULL;
    time_t expires;
    time_t timestamp;
    time_t lastmod;
    int scan1;
    int scan2;
    int scan3;
    int scan4;
    struct stat sb;
    off_t size;
    int sfileno = 0;
    int count;
    int x;

    /* load a number of objects per invocation */
    for (count = 0; count < data->speed; count++) {
	if (!fgets(data->line_in, 4095, data->log))
	    return !diskWriteIsComplete(swaplog_fd);	/* We are done */

	if ((++data->linecount & 0xFFF) == 0)
	    debug(20, 1, "  %7d Lines read so far.\n", data->linecount);

	debug(20, 9, "line_in: %s", data->line_in);
	if ((data->line_in[0] == '\0') || (data->line_in[0] == '\n') ||
	    (data->line_in[0] == '#'))
	    continue;		/* skip bad lines */

	url[0] = '\0';
	swapfile[0] = '\0';
	sfileno = 0;
	scan1 = 0;
	scan2 = 0;
	scan3 = 0;
	scan4 = 0;
	x = sscanf(data->line_in, "%x %x %x %x %d %s",
	    &sfileno,		/* swap_file_number */
	    &scan1,		/* timestamp */
	    &scan2,		/* expires */
	    &scan3,		/* last modified */
	    &scan4,		/* size */
	    url);		/* url */
	if (x > 0)
	    storeSwapFullPath(sfileno, swapfile);
	if (x != 6) {
	    if (opt_unlink_on_reload && swapfile[0])
		safeunlink(swapfile, 0);
	    continue;
	}
	timestamp = (time_t) scan1;
	expires = (time_t) scan2;
	lastmod = (time_t) scan3;
	size = (off_t) scan4;

	if (store_rebuilding != STORE_REBUILDING_FAST) {
	    if (stat(swapfile, &sb) < 0) {
		debug(20, 3, "storeRebuildFromDisk: Swap file missing: '%s': %s: %s.\n", url, swapfile, xstrerror());
		if (opt_unlink_on_reload)
		    safeunlink(swapfile, 1);
		continue;
	    }
	    /* Empty swap file? */
	    if (sb.st_size == 0) {
		if (opt_unlink_on_reload)
		    safeunlink(swapfile, 1);
		continue;
	    }
#ifdef DONT_DO_THIS
	    /* timestamp might be a little bigger than sb.st_mtime */
	    delta = (int) (timestamp - sb.st_mtime);
	    if (delta > REBUILD_TIMESTAMP_DELTA_MAX || delta < 0) {
		/* this log entry doesn't correspond to this file */
		data->clashcount++;
		continue;
	    }
#endif
	    /* Wrong size? */
	    if (sb.st_size != size) {
		/* this log entry doesn't correspond to this file */
		data->clashcount++;
		continue;
	    }
#ifdef DONT_DO_THIS
	    timestamp = sb.st_mtime;
#endif
	    debug(20, 9, "storeRebuildFromDisk: swap file exists: '%s': %s\n",
		url, swapfile);
	}
	if ((e = storeGet(url))) {
	    if (e->timestamp > timestamp) {
		/* already have a newer object in memory, throw old one away */
		debug(20, 3, "storeRebuildFromDisk: Replaced: %s\n", url);
		if (opt_unlink_on_reload)
		    safeunlink(swapfile, 1);
		data->dupcount++;
		continue;
	    }
	    debug(20, 6, "storeRebuildFromDisk: Duplicate: '%s'\n", url);
	    storeRelease(e);
	    data->objcount--;
	    data->dupcount++;
	}
	/* Is the swap file number already taken? */
	if (file_map_bit_test(sfileno)) {
	    /* Yes it is, we can't use this swapfile */
	    debug(20, 2, "storeRebuildFromDisk: Line %d Active clash: file #%d\n",
		data->linecount,
		sfileno);
	    debug(20, 3, "storeRebuildFromDisk: --> '%s'\n", url);
	    /* don't unlink the file!  just skip this log entry */
	    data->clashcount++;
	    continue;
	}
	/* update store_swap_size */
	store_swap_size += (int) ((size + 1023) >> 10);
	data->objcount++;
	e = storeAddDiskRestore(url,
	    sfileno,
	    (int) size,
	    expires,
	    timestamp,
	    lastmod);
	storeSwapLog(e);
	HTTPCacheInfo->proto_newobject(HTTPCacheInfo,
	    urlParseProtocol(url),
	    (int) size,
	    TRUE);
    }
    return 1;
}

/* meta data recreated from disk image in swap directory */
static void
storeRebuiltFromDisk(struct storeRebuild_data *data)
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

    store_rebuilding = STORE_NOT_REBUILDING;

    fclose(data->log);
    safe_free(data);
    sprintf(tmp_filename, "%s.new", swaplog_file);
    if (rename(tmp_filename, swaplog_file) < 0) {
	debug(20, 0, "storeRebuiltFromDisk: %s,%s: %s\n",
	    tmp_filename, swaplog_file, xstrerror());
	fatal_dump("storeRebuiltFromDisk: rename failed");
    }
    if (file_write_unlock(swaplog_fd, swaplog_lock) != DISK_OK)
	fatal_dump("storeRebuiltFromDisk: swaplog unlock failed");
    file_close(swaplog_fd);
    if ((swaplog_fd = file_open(swaplog_file, NULL, O_WRONLY | O_CREAT)) < 0)
	fatal_dump("storeRebuiltFromDisk: file_open(swaplog_file) failed");
    swaplog_lock = file_write_lock(swaplog_fd);
}

static void
storeStartRebuildFromDisk(void)
{
    struct stat sb;
    int i;
    struct storeRebuild_data *data;
    time_t last_clean;

    if (stat(swaplog_file, &sb) < 0) {
	debug(20, 1, "storeRebuildFromDisk: No log file\n");
	store_rebuilding = STORE_NOT_REBUILDING;
	return;
    }
    data = xcalloc(1, sizeof(*data));

    for (i = 0; i < ncache_dirs; i++)
	debug(20, 1, "Rebuilding storage from disk image in %s\n", swappath(i));
    data->start = getCurrentTime();

    /* Check if log is clean */
    sprintf(tmp_filename, "%s-last-clean", swaplog_file);
    if (stat(tmp_filename, &sb) >= 0) {
	last_clean = sb.st_mtime;
	if (stat(swaplog_file, &sb) >= 0)
	    store_rebuilding = (sb.st_mtime <= last_clean) ?
		STORE_REBUILDING_FAST : STORE_REBUILDING_SLOW;
    }
    /* Remove timestamp in case we crash during rebuild */
    safeunlink(tmp_filename, 1);
    /* close the existing write-only swaplog, and open a temporary
     * write-only swaplog  */
    if (file_write_unlock(swaplog_fd, swaplog_lock) != DISK_OK)
	fatal_dump("storeStartRebuildFromDisk: swaplog unlock failed");
    if (swaplog_fd > -1)
	file_close(swaplog_fd);
    sprintf(tmp_filename, "%s.new", swaplog_file);
    swaplog_fd = file_open(tmp_filename, NULL, O_WRONLY | O_CREAT | O_TRUNC);
    debug(20, 3, "swaplog_fd %d is now '%s'\n", swaplog_fd, tmp_filename);
    if (swaplog_fd < 0) {
	debug(20, 0, "storeStartRebuildFromDisk: %s: %s\n",
	    tmp_filename, xstrerror());
	fatal("storeStartRebuildFromDisk: Can't open tmp swaplog");
    }
    swaplog_lock = file_write_lock(swaplog_fd);
    /* Open the existing swap log for reading */
    if ((data->log = fopen(swaplog_file, "r")) == (FILE *) NULL) {
	sprintf(tmp_error_buf, "storeRebuildFromDisk: %s: %s",
	    swaplog_file, xstrerror());
	fatal(tmp_error_buf);
    }
    debug(20, 3, "data->log %d is now '%s'\n", fileno(data->log), swaplog_file);
    if (store_rebuilding == STORE_REBUILDING_FAST)
	debug(20, 1, "Rebuilding in FAST MODE.\n");

    memset(data->line_in, '\0', 4096);
    data->speed = store_rebuilding == STORE_REBUILDING_FAST ? 50 : 5;

    /* Start reading the log file */
    if (opt_foreground_rebuild) {
	while (storeDoRebuildFromDisk(data));
	storeRebuiltFromDisk(data);
    } else {
	runInBackground("storeRebuild",
	    (int (*)(void *)) storeDoRebuildFromDisk,
	    data,
	    (void (*)(void *)) storeRebuiltFromDisk);
    }
}

/* return current swap size in kilo-bytes */
int
storeGetSwapSize(void)
{
    return store_swap_size;
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
    InvokeHandlers(e);
    e->lastref = squid_curtime;
    e->store_status = STORE_OK;
    storeSetMemStatus(e, IN_MEMORY);
    e->swap_status = NO_SWAP;
    safe_free(e->mem_obj->mime_hdr);
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

    if (e->store_status != STORE_PENDING) {	/* XXX remove later */
	debug_trap("storeAbort: bad store_status");
	return;
    } else if (mem == NULL) {	/* XXX remove later */
	debug_trap("storeAbort: null mem");
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

    storeLockObject(e, NULL, NULL);

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
int
storePurgeOld(void)
{
    StoreEntry *e = NULL;
    int n = 0;
    int count = 0;
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if ((++n & 0xFF) == 0) {
	    getCurrentTime();
	    if (shutdown_pending || reread_pending)
		break;
	}
	if ((n & 0xFFF) == 0)
	    debug(20, 2, "storeWalkThrough: %7d objects so far.\n", n);
	if (storeCheckExpired(e))
	    count += storeRelease(e);
    }
    return count;
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
    if (sm_stats.n_pages_in_use + pages_needed < sm_stats.max_pages)
	return;
    if (store_rebuilding == STORE_REBUILDING_FAST)
	return;
    debug(20, 2, "storeGetMemSpace: Starting, need %d pages\n", pages_needed);

    list = xcalloc(meta_data.mem_obj_count, sizeof(ipcache_entry *));
    for (e = storeGetInMemFirst(); e; e = storeGetInMemNext()) {
	if (list_count == meta_data.mem_obj_count)
	    break;
	if (storeCheckExpired(e)) {
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
	(QS) compareSize);

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
    if (sm_stats.n_pages_in_use + pages_needed > store_pages_high) {
	store_pages_over_high = 1;
	if (squid_curtime - last_warning > 600) {
	    debug(20, 0, "WARNING: Over store_pages high-water mark (%d > %d)\n",
		sm_stats.n_pages_in_use + pages_needed, store_pages_high);
	    last_warning = squid_curtime;
	    debug(20, 0, "Perhaps you should increase cache_mem?\n");
	    i = 0;
	}
    } else {
	store_pages_over_high = 0;
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

#define SWAP_LRUSCAN_BLOCK 16
#define SWAP_MAX_HELP (store_buckets/2)

/* The maximum objects to scan for maintain storage space */
#define SWAP_LRUSCAN_COUNT	256
#define SWAP_LRU_REMOVE_COUNT	8

/* Clear Swap storage to accommodate the given object len */
int
storeGetSwapSpace(int size)
{
    static int fReduceSwap = 0;
    static int swap_help = 0;
    StoreEntry *e = NULL;
    int scanned = 0;
    int removed = 0;
    int expired = 0;
    int locked = 0;
    int locked_size = 0;
    int list_count = 0;
    int scan_count = 0;
    int max_list_count = SWAP_LRUSCAN_COUNT << 1;
    int i;
    StoreEntry **LRU_list;
    hash_link *link_ptr = NULL, *next = NULL;
    unsigned int kb_size = ((size + 1023) >> 10);

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
	int expired_in_one_bucket = 0;
	link_ptr = hash_get_bucket(store_table, storeGetBucketNum());
	if (link_ptr == NULL)
	    continue;
	/* this while loop handles one bucket of hash table */
	expired_in_one_bucket = 0;
	for (; link_ptr; link_ptr = next) {
	    if (list_count == max_list_count)
		break;
	    scanned++;
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;
	    if (storeCheckExpired(e)) {
		debug(20, 3, "storeGetSwapSpace: Expired '%s'\n", e->url);
		expired_in_one_bucket += storeRelease(e);
	    } else if (!storeEntryLocked(e)) {
		*(LRU_list + list_count) = e;
		list_count++;
		scan_count++;
	    } else {
		locked++;
		locked_size += e->mem_obj->e_current_len;
	    }
	}			/* while, end of one bucket of hash table */
	expired += expired_in_one_bucket;
	if (expired_in_one_bucket &&
	    ((!fReduceSwap && (store_swap_size + kb_size <= store_swap_high)) ||
		(fReduceSwap && (store_swap_size + kb_size <= store_swap_low)))
	    ) {
	    fReduceSwap = 0;
	    safe_free(LRU_list);
	    debug(20, 2, "storeGetSwapSpace: Finished, %d objects expired.\n",
		expired);
	    return 0;
	}
	qsort((char *) LRU_list,
	    list_count,
	    sizeof(StoreEntry *),
	    (QS) compareLastRef);
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
	if (++swap_help > SWAP_MAX_HELP) {
	    debug(20, 0, "storeGetSwapSpace: Nothing to free with %d Kbytes in use.\n",
		store_swap_size);
	    debug(20, 0, "--> Asking for %d bytes\n", size);
	    debug(20, 0, "WARNING! Repeated failures to allocate swap space!\n");
	    debug(20, 0, "WARNING! Please check your disk space.\n");
	    swap_help = 0;
	} else {
	    debug(20, 2, "storeGetSwapSpace: Nothing to free with %d Kbytes in use.\n",
		store_swap_size);
	    debug(20, 2, "--> Asking for %d bytes\n", size);
	}
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
    StoreEntry *result = NULL;
    StoreEntry *hentry = NULL;
    hash_link *hptr = NULL;
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
    if (e->key != NULL) {
	if ((hptr = hash_lookup(store_table, e->key)) == NULL) {
	    debug(20, 0, "storeRelease: Not Found: '%s'\n", e->key);
	    debug(20, 0, "Dump of Entry 'e':\n %s\n", storeToString(e));
	    debug_trap("storeRelease: Invalid Entry");
	    return 0;
	}
	result = (StoreEntry *) hptr;
	if (result != e) {
	    debug(20, 0, "storeRelease: Duplicated entry? '%s'\n",
		result->url ? result->url : "NULL");
	    debug(20, 0, "Dump of Entry 'e':\n%s", storeToString(e));
	    debug(20, 0, "Dump of Entry 'result':\n%s", storeToString(result));
	    debug_trap("storeRelease: Duplicate Entry");
	    return 0;
	}
    }
    /* check if coresponding HEAD object exists. */
    if (e->method == METHOD_GET) {
	hkey = storeGeneratePublicKey(e->url, METHOD_HEAD);
	if ((hentry = (StoreEntry *) hash_lookup(store_table, hkey)))
	    storeExpireNow(hentry);
    }
    if (store_rebuilding == STORE_REBUILDING_FAST) {
	debug(20, 2, "storeRelease: Delaying release until store is rebuilt: '%s'\n",
	    e->key ? e->key : e->url ? e->url : "NO URL");
	storeExpireNow(e);
	storeSetPrivateKey(e);
	return 0;
    }
    if (e->key)
	debug(20, 5, "storeRelease: Release object key: %s\n", e->key);
    else
	debug(20, 5, "storeRelease: Release anonymous object\n");

    if (e->swap_status == SWAP_OK && (e->swap_file_number > -1)) {
	(void) safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
	file_map_bit_reset(e->swap_file_number);
	e->swap_file_number = -1;
	store_swap_size -= (e->object_len + 1023) >> 10;
	HTTPCacheInfo->proto_purgeobject(HTTPCacheInfo,
	    urlParseProtocol(e->url),
	    e->object_len);
    }
    storeHashDelete(e);
    storeLog(STORE_LOG_RELEASE, e);
    destroy_StoreEntry(e);
    return 1;
}


/* return if the current key is the original one. */
int
storeOriginalKey(const StoreEntry * e)
{
    if (!e)
	return 1;
    return !(e->flag & KEY_CHANGE);
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

/*  use this for internal call only */
static int
storeCopy(const StoreEntry * e, int stateoffset, int maxSize, char *buf, int *size)
{
    int available_to_write = 0;

    available_to_write = e->mem_obj->e_current_len - stateoffset;

    if (stateoffset < e->mem_obj->e_lowest_offset) {
	/* this should not happen. Logic race !!! */
	debug(20, 1, "storeCopy: Client Request a chunk of data in area lower than the lowest_offset\n");
	debug(20, 1, "           Current Lowest offset : %d\n", e->mem_obj->e_lowest_offset);
	debug(20, 1, "           Requested offset      : %d\n", stateoffset);
	/* can't really do anything here. Client may hang until lifetime runout. */
	return 0;
    }
    *size = (available_to_write >= maxSize) ?
	maxSize : available_to_write;

    debug(20, 6, "storeCopy: avail_to_write=%d, store_offset=%d\n",
	*size, stateoffset);

    if (*size > 0)
	(void) e->mem_obj->data->mem_copy(e->mem_obj->data, stateoffset, buf, *size);

    return *size;
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
	    if (mem->clients[i].fd != -1)
		return 1;
	}
    }
    return 0;
}

static int
storeClientListSearch(const MemObject * mem, int fd)
{
    int i;
    if (mem->clients) {
	for (i = 0; i < mem->nclients; i++) {
	    if (mem->clients[i].fd == -1)
		continue;
	    if (mem->clients[i].fd != fd)
		continue;
	    return i;
	}
    }
    return -1;
}

/* add client with fd to client list */
int
storeClientListAdd(StoreEntry * e, int fd, int last_offset)
{
    int i;
    MemObject *mem = e->mem_obj;
    struct _store_client *oldlist = NULL;
    int oldsize;
    /* look for empty slot */
    if (mem->clients == NULL) {
	mem->nclients = MIN_CLIENT;
	mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
	for (i = 0; i < mem->nclients; i++)
	    mem->clients[i].fd = -1;
    }
    for (i = 0; i < mem->nclients; i++) {
	if (mem->clients[i].fd == -1)
	    break;
    }
    if (i == mem->nclients) {
	debug(20, 3, "storeClientListAdd: FD %d Growing clients for '%s'\n",
	    fd, e->url);
	oldlist = mem->clients;
	oldsize = mem->nclients;
	mem->nclients <<= 1;
	mem->clients = xcalloc(mem->nclients, sizeof(struct _store_client));
	for (i = 0; i < oldsize; i++)
	    mem->clients[i] = oldlist[i];
	for (; i < mem->nclients; i++)
	    mem->clients[i].fd = -1;
	safe_free(oldlist);
	i = oldsize;
    }
    mem->clients[i].fd = fd;
    mem->clients[i].last_offset = last_offset;
    return i;
}

/* same to storeCopy but also register client fd and last requested offset
 * for each client */
int
storeClientCopy(StoreEntry * e,
    int stateoffset,
    int maxSize,
    char *buf,
    int *size,
    int fd)
{
    int ci;
    int sz;
    MemObject *mem = e->mem_obj;
    int available_to_write = mem->e_current_len - stateoffset;
    if (stateoffset < mem->e_lowest_offset) {
	debug_trap("storeClientCopy: requested offst < lowest offset");
	debug(20, 0, "--> '%s'\n", e->url);
	*size = 0;
	return 0;
    }
    if ((ci = storeClientListSearch(mem, fd)) < 0) {
	debug_trap("storeClientCopy: Unregistered client");
	debug(20, 0, "--> '%s'\n", e->url);
	*size = 0;
	return 0;
    }
    sz = (available_to_write >= maxSize) ? maxSize : available_to_write;
    /* update the lowest requested offset */
    mem->clients[ci].last_offset = stateoffset + sz;
    if (sz > 0)
	(void) mem->data->mem_copy(mem->data, stateoffset, buf, sz);
    /* see if we can get rid of some data if we are in "delete behind" mode . */
    if (BIT_TEST(e->flag, DELETE_BEHIND))
	storeDeleteBehind(e);
    *size = sz;
    return sz;
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

static int
storeVerifySwapDirs(int clean)
{
    int inx;
    const char *path = NULL;
    struct stat sb;
    int directory_created = 0;
    char *cmdbuf = NULL;

    for (inx = 0; inx < ncache_dirs; inx++) {
	path = swappath(inx);
	debug(20, 9, "storeVerifySwapDirs: Creating swap space in %s\n", path);
	if (stat(path, &sb) < 0) {
	    /* we need to create a directory for swap file here. */
	    if (mkdir(path, 0777) < 0) {
		if (errno != EEXIST) {
		    sprintf(tmp_error_buf, "Failed to create swap directory %s: %s",
			path,
			xstrerror());
		    fatal(tmp_error_buf);
		}
	    }
	    if (stat(path, &sb) < 0) {
		sprintf(tmp_error_buf,
		    "Failed to verify swap directory %s: %s",
		    path, xstrerror());
		fatal(tmp_error_buf);
	    }
	    debug(20, 1, "storeVerifySwapDirs: Created swap directory %s\n", path);
	    directory_created = 1;
	}
	if (clean && opt_unlink_on_reload) {
	    debug(20, 1, "storeVerifySwapDirs: Zapping all objects on disk storage.\n");
	    /* This could be dangerous, second copy of cache can destroy
	     * the existing swap files of the previous cache. We may
	     * use rc file do it. */
	    cmdbuf = xcalloc(1, BUFSIZ);
	    sprintf(cmdbuf, "cd %s; /bin/rm -rf log [0-9][0-9]", path);
	    debug(20, 1, "storeVerifySwapDirs: Running '%s'\n", cmdbuf);
	    system(cmdbuf);	/* XXX should avoid system(3) */
	    xfree(cmdbuf);
	}
    }
    return directory_created;
}

static void
storeCreateSwapSubDirs(void)
{
    int i, j, k;
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (j = 0; j < ncache_dirs; j++) {
	for (i = 0; i < SWAP_DIRECTORIES_L1; i++) {
	    sprintf(name, "%s/%02X", swappath(j), i);
	    debug(20, 1, "Making directories in %s\n", name);
	    if (mkdir(name, 0755) < 0) {
		if (errno != EEXIST) {
		    sprintf(tmp_error_buf,
			"Failed to make swap directory %s: %s",
			name, xstrerror());
		    fatal(tmp_error_buf);
		}
	    }
	    for (k = 0; k < SWAP_DIRECTORIES_L2; k++) {
		sprintf(name, "%s/%02X/%02X", swappath(j), i, k);
		if (mkdir(name, 0755) < 0) {
		    if (errno != EEXIST) {
			sprintf(tmp_error_buf,
			    "Failed to make swap directory %s: %s",
			    name, xstrerror());
			fatal(tmp_error_buf);
		    }
		}
	    }
	}
    }
}

static void
storeInitHashValues(void)
{
    int i;
    /* Calculate size of hash table (maximum currently 64k buckets).  */
    i = Config.Swap.maxSize / Config.Store.avgObjectSize;
    debug(20, 1, "Swap maxSize %d, estimated %d objects\n",
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
    int dir_created = 0;
    wordlist *w = NULL;
    char *fname = NULL;
    file_map_create(MAX_SWAP_FILE);
    storeInitHashValues();
    storeCreateHashTable(urlcmp);
    if (strcmp((fname = Config.Log.store), "none") == 0)
	storelog_fd = -1;
    else
	storelog_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (storelog_fd < 0)
	debug(20, 1, "Store logging disabled\n");
    for (w = Config.cache_dirs; w; w = w->next)
	storeAddSwapDisk(w->key);
    storeSanityCheck();
    dir_created = storeVerifySwapDirs(opt_zap_disk_store);
    if (Config.Log.swap)
	strncpy(swaplog_file, Config.Log.swap, SQUID_MAXPATHLEN);
    else
	sprintf(swaplog_file, "%s/log", swappath(0));
    swaplog_fd = file_open(swaplog_file, NULL, O_WRONLY | O_CREAT);
    debug(20, 3, "swaplog_fd %d is now '%s'\n", swaplog_fd, swaplog_file);
    if (swaplog_fd < 0) {
	sprintf(tmp_error_buf, "Cannot open swap logfile: %s", swaplog_file);
	fatal(tmp_error_buf);
    }
    swaplog_lock = file_write_lock(swaplog_fd);
    if (!opt_zap_disk_store)
	storeStartRebuildFromDisk();
    else
	store_rebuilding = STORE_NOT_REBUILDING;
    if (dir_created || opt_zap_disk_store)
	storeCreateSwapSubDirs();
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

/* 
 *  storeSanityCheck - verify that all swap storage areas exist, and
 *  are writable; otherwise, force -z.
 */
static void
storeSanityCheck(void)
{
    LOCAL_ARRAY(char, name, 4096);
    int i;

    if (ncache_dirs < 1)
	storeAddSwapDisk(DefaultSwapDir);

    for (i = 0; i < SWAP_DIRECTORIES_L1; i++) {
	sprintf(name, "%s/%02X", swappath(i), i);
	errno = 0;
	if (access(name, W_OK)) {
	    /* A very annoying problem occurs when access() fails because
	     * the system file table is full.  To prevent squid from
	     * deleting your entire disk cache on a whim, insist that the
	     * errno indicates that the directory doesn't exist */
	    if (errno != ENOENT)
		continue;
	    debug(20, 0, "WARNING: Cannot write to swap directory '%s'\n",
		name);
	    debug(20, 0, "Forcing a *full restart* (e.g., %s -z)...\n",
		appname);
	    opt_zap_disk_store = 1;
	    return;
	}
    }
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
int
storeMaintainSwapSpace(void)
{
    static time_t last_time = 0;
    static unsigned int bucket = 0;
    hash_link *link_ptr = NULL, *next = NULL;
    StoreEntry *e = NULL;
    int rm_obj = 0;
    int scan_buckets;
    int scan_obj = 0;

    /* We can't delete objects while rebuilding swap */
    if (store_rebuilding == STORE_REBUILDING_FAST)
	return -1;

    /* Purges expired objects, check one bucket on each calling */
    if (squid_curtime - last_time >= store_maintain_rate) {
	for (scan_buckets = store_maintain_buckets; scan_buckets > 0;
	    scan_buckets--) {
	    last_time = squid_curtime;
	    if (bucket >= store_buckets) {
		bucket = 0;
		scan_revolutions++;
		debug(20, 1, "Completed %d full expiration scans of store table\n",
		    scan_revolutions);
	    }
	    next = hash_get_bucket(store_table, bucket++);
	    while ((link_ptr = next)) {
		scan_obj++;
		next = link_ptr->next;
		e = (StoreEntry *) link_ptr;
		if (!storeCheckExpired(e))
		    continue;
		rm_obj += storeRelease(e);
	    }
	}
    }
    debug(20, rm_obj ? 1 : 2, "Scanned %d objects, Removed %d expired objects\n", scan_obj, rm_obj);

    /* Scan row of hash table each second and free storage if we're
     * over the high-water mark */
    storeGetSwapSpace(0);

    return rm_obj;
}


/*
 *  storeWriteCleanLog
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
int
storeWriteCleanLog(void)
{
    StoreEntry *e = NULL;
    FILE *fp = NULL;
    int n = 0;
    int x = 0;
    time_t start, stop, r;

    if (store_rebuilding) {
	debug(20, 1, "storeWriteCleanLog: Not currently OK to rewrite swap log.\n");
	debug(20, 1, "storeWriteCleanLog: Operation aborted.\n");
	return 0;
    }
    debug(20, 1, "storeWriteCleanLog: Starting...\n");
    start = getCurrentTime();
    sprintf(tmp_filename, "%s_clean", swaplog_file);
    if ((fp = fopen(tmp_filename, "a+")) == NULL) {
	debug(20, 0, "storeWriteCleanLog: %s: %s\n", tmp_filename, xstrerror());
	return 0;
    }
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
	x = fprintf(fp, "%08x %08x %08x %08x %9d %s\n",
	    (int) e->swap_file_number,
	    (int) e->timestamp,
	    (int) e->expires,
	    (int) e->lastmod,
	    e->object_len,
	    e->url);
	if (x < 0) {
	    debug(20, 0, "storeWriteCleanLog: %s: %s\n", tmp_filename, xstrerror());
	    debug(20, 0, "storeWriteCleanLog: Current swap logfile not replaced.\n");
	    fclose(fp);
	    safeunlink(tmp_filename, 0);
	    return 0;
	}
	if ((++n & 0xFFF) == 0) {
	    getCurrentTime();
	    debug(20, 1, "  %7d lines written so far.\n", n);
	}
    }
    if (fclose(fp) < 0) {
	debug(20, 0, "storeWriteCleanLog: %s: %s\n", tmp_filename, xstrerror());
	debug(20, 0, "storeWriteCleanLog: Current swap logfile not replaced.\n");
	safeunlink(tmp_filename, 0);
	return 0;
    }
    if (file_write_unlock(swaplog_fd, swaplog_lock) != DISK_OK) {
	debug(20, 0, "storeWriteCleanLog: Failed to unlock swaplog!\n");
	debug(20, 0, "storeWriteCleanLog: Current swap logfile not replaced.\n");
	return 0;
    }
    if (rename(tmp_filename, swaplog_file) < 0) {
	debug(20, 0, "storeWriteCleanLog: rename failed: %s\n",
	    xstrerror());
	return 0;
    }
    file_close(swaplog_fd);
    swaplog_fd = file_open(swaplog_file, NULL, O_WRONLY | O_CREAT);
    if (swaplog_fd < 0) {
	sprintf(tmp_error_buf, "Cannot open swap logfile: %s", swaplog_file);
	fatal(tmp_error_buf);
    }
    swaplog_lock = file_write_lock(swaplog_fd);

    stop = getCurrentTime();
    r = stop - start;
    debug(20, 1, "  Finished.  Wrote %d lines.\n", n);
    debug(20, 1, "  Took %d seconds (%6.1lf lines/sec).\n",
	r > 0 ? r : 0, (double) n / (r > 0 ? r : 1));

    /* touch a timestamp file */
    sprintf(tmp_filename, "%s-last-clean", swaplog_file);
    file_close(file_open(tmp_filename, NULL, O_WRONLY | O_CREAT | O_TRUNC));
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
	if (mem->clients[i].fd == -1)
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

    if (storelog_fd > -1) {
	file_close(storelog_fd);
	storelog_fd = -1;
    }
    if ((fname = Config.Log.store) == NULL)
	return;

    if (strcmp(fname, "none") == 0)
	return;

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
    storelog_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (storelog_fd < 0) {
	debug(20, 0, "storeRotateLog: %s: %s\n", fname, xstrerror());
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
storeCheckExpired(const StoreEntry * e)
{
    if (storeEntryLocked(e))
	return 0;
    if (BIT_TEST(e->flag, ENTRY_NEGCACHED) && squid_curtime >= e->expires)
	return 1;
    if (Config.referenceAge && squid_curtime - e->lastref > Config.referenceAge)
	return 1;
    return 0;
}

static const char *
storeDescribeStatus(const StoreEntry * e)
{
    static char buf[MAX_URL << 1];
    sprintf(buf, "mem:%13s ping:%12s store:%13s swap:%12s locks:%d %s\n",
	memStatusStr[e->mem_status],
	pingStatusStr[e->ping_status],
	storeStatusStr[e->store_status],
	swapStatusStr[e->swap_status],
	(int) e->lock_count,
	e->url);
    return buf;
}

void
storeCloseLog(void)
{
    if (swaplog_fd >= 0)
	file_close(swaplog_fd);
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
}

int
expiresMoreThan(time_t expires, time_t when)
{
    if (expires < 0)
	return 0;
    return (expires > squid_curtime + when);
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

