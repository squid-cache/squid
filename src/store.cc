/*
 * $Id: store.cc,v 1.79 1996/08/12 23:37:25 wessels Exp $
 *
 * DEBUG: section 20    Storeage Manager
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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
#define SWAP_DIRECTORIES_L1	16
#define SWAP_DIRECTORIES_L2	256

#define WITH_MEMOBJ	1
#define WITHOUT_MEMOBJ	0

/* rate of checking expired objects in main loop */
#define STORE_MAINTAIN_RATE	(10)

#define STORE_BUCKETS		(7921)
#define STORE_IN_MEM_BUCKETS		(143)

#define STORE_LOG_CREATE	0
#define STORE_LOG_SWAPIN	1
#define STORE_LOG_SWAPOUT	2
#define STORE_LOG_RELEASE	3

static char *storeLogTags[] =
{
    "CREATE",
    "SWAPIN",
    "SWAPOUT",
    "RELEASE"
};

char *memStatusStr[] =
{
    "NOT_IN_MEMORY",
    "SWAPPING_IN",
    "IN_MEMORY"
};

char *pingStatusStr[] =
{
    "PING_WAITING",
    "PING_TIMEOUT",
    "PING_DONE",
    "PING_NONE"
};

char *storeStatusStr[] =
{
    "STORE_OK",
    "STORE_PENDING",
    "STORE_ABORTED"
};

char *swapStatusStr[] =
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
static int storeSwapInStart _PARAMS((StoreEntry *, SIH, void *));
static void destroy_MemObject _PARAMS((MemObject *));
static void destroy_MemObjectData _PARAMS((MemObject *));
static void destroy_StoreEntry _PARAMS((StoreEntry *));
static MemObject *new_MemObject _PARAMS((void));
static mem_ptr new_MemObjectData _PARAMS((void));
static StoreEntry *new_StoreEntry _PARAMS((int mem_obj_flag));
static int storeCheckPurgeMem _PARAMS((StoreEntry * e));
static void storeSwapLog _PARAMS((StoreEntry *));
static int storeHashDelete _PARAMS((StoreEntry *));


/* Now, this table is inaccessible to outsider. They have to use a method
 * to access a value in internal storage data structure. */
HashID store_table = 0;
/* hash table for in-memory-only objects */
HashID in_mem_table = 0;

/* current memory storage size */
static unsigned long store_mem_size = 0;
static unsigned long store_mem_high = 0;
static unsigned long store_mem_low = 0;

/* current hotvm object */
/* defaults for 16M cache and 12.5 cache_hot_vm_factor */
static int store_hotobj_high = 180;
static int store_hotobj_low = 120;


/* current file name, swap file, use number as a filename */
static unsigned long swapfileno = 0;
static int store_swap_size = 0;	/* kilobytes !! */
static unsigned long store_swap_high = 0;
static unsigned long store_swap_low = 0;
static int swaplog_fd = -1;
static int swaplog_lock = 0;
static int storelog_fd = -1;

/* key temp buffer */
static char key_temp_buffer[MAX_URL + 100];
static char swaplog_file[MAX_FILE_NAME_LEN];
static char tmp_filename[MAX_FILE_NAME_LEN];

/* patch cache_dir to accomodate multiple disk storage */
dynamic_array *cache_dirs = NULL;
int ncache_dirs = 0;

static MemObject *new_MemObject()
{
    MemObject *mem = get_free_mem_obj();
    mem->reply = xcalloc(1, sizeof(struct _http_reply));
    meta_data.store_in_mem_objects++;
    meta_data.misc += sizeof(struct _http_reply);
    debug(20, 3, "new_MemObject: returning %p\n", mem);
    return mem;
}

static StoreEntry *new_StoreEntry(mem_obj_flag)
     int mem_obj_flag;
{
    StoreEntry *e = NULL;

    e = xcalloc(1, sizeof(StoreEntry));
    meta_data.store_entries++;
    if (mem_obj_flag)
	e->mem_obj = new_MemObject();
    debug(20, 3, "new_StoreEntry: returning %p\n", e);
    return e;
}

static void destroy_MemObject(mem)
     MemObject *mem;
{
    int i;
    debug(20, 3, "destroy_MemObject: destroying %p\n", mem);
    destroy_MemObjectData(mem);
    safe_free(mem->pending);
    if (mem->client_list) {
	for (i = 0; i < mem->client_list_size; ++i) {
	    if (mem->client_list[i])
		safe_free(mem->client_list[i]);
	}
	safe_free(mem->client_list);
    }
    safe_free(mem->mime_hdr);
    safe_free(mem->reply);
    safe_free(mem->e_abort_msg);
    requestUnlink(mem->request);
    mem->request = NULL;
    memset(mem, '\0', sizeof(MemObject));
    put_free_mem_obj(mem);
    meta_data.store_in_mem_objects--;
    meta_data.misc -= sizeof(struct _http_reply);
}

static void destroy_StoreEntry(e)
     StoreEntry *e;
{
    debug(20, 3, "destroy_StoreEntry: destroying %p\n", e);
    if (!e)
	fatal_dump("destroy_StoreEntry: NULL Entry");
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

static mem_ptr new_MemObjectData()
{
    debug(20, 3, "new_MemObjectData: calling memInit()\n");
    meta_data.hot_vm++;
    return memInit();
}

static void destroy_MemObjectData(mem)
     MemObject *mem;
{
    debug(20, 3, "destroy_MemObjectData: destroying %p\n", mem->data);
    store_mem_size -= mem->e_current_len - mem->e_lowest_offset;
    debug(20, 8, "destroy_MemObjectData: Freeing %d in-memory bytes\n",
	mem->e_current_len);
    debug(20, 8, "destroy_MemObjectData: store_mem_size = %d\n",
	store_mem_size);
    if (mem->data) {
	mem->data->mem_free(mem->data);
	mem->data = NULL;
	meta_data.hot_vm--;
    }
    mem->e_current_len = 0;
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

/*
 * Create 2 hash tables, "table" has all objects, "in_mem_table" has only
 * objects in the memory.
 */

HashID storeCreateHashTable(cmp_func)
     int (*cmp_func) (char *, char *);
{
    store_table = hash_create(cmp_func, STORE_BUCKETS, hash_url);
    in_mem_table = hash_create(cmp_func, STORE_IN_MEM_BUCKETS, hash_url);
    return store_table;
}

/*
 * if object is in memory, also insert into in_mem_table
 */

static int storeHashInsert(e)
     StoreEntry *e;
{
    debug(20, 3, "storeHashInsert: Inserting Entry %p key '%s'\n",
	e, e->key);
    if (e->mem_status == IN_MEMORY)
	hash_insert(in_mem_table, e->key, e);
    return (hash_join(store_table, (hash_link *) e));
}

/*
 * if object in memory, also remove from in_mem_table
 */

static int storeHashDelete(e)
     StoreEntry *e;
{
    hash_link *hptr = NULL;
    if (e->mem_status == IN_MEMORY && e->key) {
	if ((hptr = hash_lookup(in_mem_table, e->key)))
	    hash_delete_link(in_mem_table, hptr);
    }
    return (hash_remove_link(store_table, (hash_link *) e));
}

/*
 * maintain the in-mem hash table according to the changes of mem_status
 * This routine replaces the instruction "e->store_status = status;"
 */

void storeSetMemStatus(e, status)
     StoreEntry *e;
     mem_status_t status;
{
    hash_link *ptr = NULL;

    if (e->key == NULL)
	fatal_dump("storeSetMemStatus: NULL key");

    if (status != IN_MEMORY && e->mem_status == IN_MEMORY) {
	if ((ptr = hash_lookup(in_mem_table, e->key)))
	    hash_delete_link(in_mem_table, ptr);
    } else if (status == IN_MEMORY && e->mem_status != IN_MEMORY) {
	hash_insert(in_mem_table, e->key, e);
    }
    e->mem_status = status;
}

/* -------------------------------------------------------------------------- */

static char *time_describe(t)
     time_t t;
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

static void storeLog(tag, e)
     int tag;
     StoreEntry *e;
{
    LOCAL_ARRAY(char, logmsg, MAX_URL << 1);
    time_t t;
    int expect_len = 0;
    int actual_len = 0;
    int code = 0;
    if (storelog_fd < 0)
	return;
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
void storePurgeMem(e)
     StoreEntry *e;
{
    debug(20, 3, "storePurgeMem: Freeing memory-copy of %s\n", e->key);
    if (e->mem_obj == NULL)
	return;
    if (storeEntryLocked(e)) {
	debug(20, 0, "storePurgeMem: someone is purging a locked object?\n");
	debug(20, 0, "%s", storeToString(e));
	fatal_dump(NULL);
    }
    storeSetMemStatus(e, NOT_IN_MEMORY);
    destroy_MemObject(e->mem_obj);
    e->mem_obj = NULL;
}

/* lock the object for reading, start swapping in if necessary */
/* Called by:
 * icp_hit_or_miss()
 * storeAbort()
 * {http,ftp,gopher,wais}Start()
 */
int storeLockObject(e, handler, data)
     StoreEntry *e;
     SIH handler;
     void *data;
{
    int swap_in_stat = 0;
    int status = 0;

    e->lock_count++;
    debug(20, 3, "storeLockObject: locks %d: '%s'\n", e->lock_count, e->key);

    if ((e->mem_status == NOT_IN_MEMORY) &&	/* Not in memory */
	(e->swap_status != SWAP_OK) &&	/* Not on disk */
	(e->store_status != STORE_PENDING)	/* Not being fetched */
	) {
	debug(20, 0, "storeLockObject: NOT_IN_MEMORY && !SWAP_OK && !STORE_PENDING conflict: <URL:%s>. aborting...\n", e->url);
	/* If this sanity check fails, we should just ... */
	fatal_dump(NULL);
    }
    e->lastref = squid_curtime;

    /* If the object is NOT_IN_MEMORY, fault it in. */
    if ((e->mem_status == NOT_IN_MEMORY) && (e->swap_status == SWAP_OK)) {
	/* object is in disk and no swapping daemon running. Bring it in. */
	if ((swap_in_stat = storeSwapInStart(e, handler, data)) < 0) {
	    /*
	     * We couldn't find or couldn't open object's swapfile.
	     * So, return a -1 here, indicating that we will treat
	     * the reference like a MISS_TTL, force a keychange and
	     storeRelease.  */
	    e->lock_count--;
	}
	status = swap_in_stat;
    } else if (e->mem_status == IN_MEMORY && handler) {
	/* its already in memory, so call the handler */
	(*handler) (0, data);
    } else if (handler) {
	/* The object is probably in state SWAPPING_IN, not much we can do.
	 * Instead of returning failure here, we should have a list of complete
	 * handlers which we could append to... */
	(*handler) (1, data);
    }
    return status;
}

void storeReleaseRequest(e)
     StoreEntry *e;
{
    if (e->flag & RELEASE_REQUEST)
	return;
    if (!storeEntryLocked(e))
	fatal_dump("Somebody called storeReleaseRequest on an unlocked entry");
    debug(20, 3, "storeReleaseRequest: FOR '%s'\n", e->key ? e->key : e->url);
    e->flag |= RELEASE_REQUEST;
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */
int storeUnlockObject(e)
     StoreEntry *e;
{
    int lock_count;

    if ((int) e->lock_count > 0)
	e->lock_count--;
    else if (e->lock_count == 0) {
	debug(20, 0, "Entry lock count %d is out-of-whack\n", e->lock_count);
    }
    debug(20, 3, "storeUnlockObject: key '%s' count=%d\n", e->key, e->lock_count);

    if (e->lock_count)
	return e->lock_count;

    /* Prevent UMR if we end up freeing the entry */
    lock_count = (int) e->lock_count;

    if (e->flag & RELEASE_REQUEST) {
	storeRelease(e);
    } else if (e->flag & ABORT_MSG_PENDING) {
	/* This is where the negative cache gets storeAppended */
	/* Briefly lock to replace content with abort message */
	e->lock_count++;
	destroy_MemObjectData(e->mem_obj);
	e->object_len = 0;
	e->mem_obj->data = new_MemObjectData();
	storeAppend(e, e->mem_obj->e_abort_msg, strlen(e->mem_obj->e_abort_msg));
	e->object_len = e->mem_obj->e_current_len
	    = strlen(e->mem_obj->e_abort_msg);
	BIT_RESET(e->flag, ABORT_MSG_PENDING);
	e->lock_count--;
    } else if (storeCheckPurgeMem(e)) {
	storePurgeMem(e);
    }
    return lock_count;
}

/* Lookup an object in the cache. 
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *storeGet(url)
     char *url;
{
    hash_link *hptr = NULL;

    debug(20, 3, "storeGet: looking up %s\n", url);

    if ((hptr = hash_lookup(store_table, url)) != NULL)
	return (StoreEntry *) hptr;
    return NULL;
}

unsigned int getKeyCounter()
{
    static unsigned int key_counter = 0;
    if (++key_counter == 0)
	++key_counter;
    return key_counter;
}

char *storeGeneratePrivateKey(url, method, num)
     char *url;
     method_t method;
     int num;
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

char *storeGeneratePublicKey(url, method)
     char *url;
     method_t method;
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
	fatal_dump("storeGeneratePublicKey: Unsupported request method");
	break;
    }
    return NULL;
}

void storeSetPrivateKey(e)
     StoreEntry *e;
{
    StoreEntry *e2 = NULL;
    hash_link *table_entry = NULL;
    char *newkey = NULL;

    if (e->key && BIT_TEST(e->flag, KEY_PRIVATE))
	return;			/* is already private */

    newkey = storeGeneratePrivateKey(e->url, e->method, 0);
    if ((table_entry = hash_lookup(store_table, newkey))) {
	e2 = (StoreEntry *) table_entry;
	debug(20, 0, "storeSetPrivateKey: Entry already exists with key '%s'\n",
	    newkey);
	debug(20, 0, "storeSetPrivateKey: Entry Dump:\n%s\n", storeToString(e2));
	fatal_dump("Private key already exists.");
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

void storeSetPublicKey(e)
     StoreEntry *e;
{
    StoreEntry *e2 = NULL;
    hash_link *table_entry = NULL;
    char *newkey = NULL;
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

StoreEntry *storeCreateEntry(url, req_hdr, flags, method)
     char *url;
     char *req_hdr;
     int flags;
     method_t method;
{
    StoreEntry *e = NULL;
    MemObject *mem = NULL;
    debug(20, 3, "storeCreateEntry: '%s' icp flags=%x\n", url, flags);

    if (meta_data.hot_vm > store_hotobj_high)
	storeGetMemSpace(0, 1);
    e = new_StoreEntry(WITH_MEMOBJ);
    e->lock_count = 1;		/* Note lock here w/o calling storeLock() */
    mem = e->mem_obj;
    e->url = xstrdup(url);
    meta_data.url_strings += strlen(url);
    e->method = method;
    if (req_hdr)
	mem->mime_hdr = xstrdup(req_hdr);
    if (BIT_TEST(flags, REQ_NOCACHE))
	BIT_SET(e->flag, REFRESH_REQUEST);
    if (BIT_TEST(flags, REQ_CACHABLE)) {
	BIT_SET(e->flag, CACHABLE);
	BIT_RESET(e->flag, RELEASE_REQUEST);
    } else {
	BIT_RESET(e->flag, CACHABLE);
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
    if (BIT_TEST(flags, REQ_HTML))
	BIT_SET(e->flag, ENTRY_HTML);

    e->store_status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = NO_SWAP;
    e->swap_file_number = -1;
    mem->data = new_MemObjectData();
    e->refcount = 0;
    e->lastref = squid_curtime;
    e->timestamp = 0;		/* set in storeSwapOutHandle() */
    e->ping_status = PING_NONE;

    /* allocate pending list */
    mem->pending_list_size = MIN_PENDING;
    mem->pending = (struct pentry **)
	xcalloc(mem->pending_list_size, sizeof(struct pentry *));

    /* allocate client list */
    mem->client_list_size = MIN_CLIENT;
    mem->client_list = (ClientStatusEntry **)
	xcalloc(mem->client_list_size, sizeof(ClientStatusEntry *));
    /* storeLog(STORE_LOG_CREATE, e); */
    return e;

}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
StoreEntry *storeAddDiskRestore(url, file_number, size, expires, timestamp, lastmod)
     char *url;
     int file_number;
     int size;
     time_t expires;
     time_t timestamp;
     time_t lastmod;
{
    StoreEntry *e = NULL;

    debug(20, 5, "StoreAddDiskRestore: <URL:%s>: size %d: expires %d: file_number %d\n",
	url, size, expires, file_number);

    /* if you call this you'd better be sure file_number is not 
     * already in use! */

    meta_data.url_strings += strlen(url);

    e = new_StoreEntry(WITHOUT_MEMOBJ);
    e->url = xstrdup(url);
    e->method = METHOD_GET;
    storeSetPublicKey(e);
    BIT_SET(e->flag, CACHABLE);
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
    e->lastref = squid_curtime;
    e->timestamp = timestamp;
    e->expires = expires;
    e->lastmod = lastmod;
    e->ping_status = PING_NONE;
    return e;
}

/* Register interest in an object currently being retrieved. */
int storeRegister(e, fd, handler, data)
     StoreEntry *e;
     int fd;
     PIF handler;
     void *data;
{
    PendingEntry *pe = NULL;
    int old_size;
    int i;
    int j;
    MemObject *mem = e->mem_obj;

    debug(20, 3, "storeRegister: FD %d '%s'\n", fd, e->key);

    pe = xcalloc(1, sizeof(PendingEntry));
    pe->fd = fd;
    pe->handler = handler;
    pe->data = data;

    /* 
     *  I've rewritten all this pendings stuff so that num_pending goes
     *  away, and to fix all of the 'array bounds' problems we were having.
     *  It's now a very simple array, with any NULL slot empty/avail.
     *  If something needs to be added and there are no empty slots,
     *  it'll grow the array.
     */
    /* find an empty slot */
    for (i = 0; i < (int) mem->pending_list_size; i++) {
	if (mem->pending[i] == NULL)
	    break;
    }

    if (i == mem->pending_list_size) {
	/* grow the array */
	struct pentry **tmp = NULL;

	old_size = mem->pending_list_size;

	/* set list_size to an appropriate amount */
	mem->pending_list_size += MIN_PENDING;

	/* allocate, and copy old pending list over to the new one */
	tmp = xcalloc(mem->pending_list_size, sizeof(struct pentry *));
	for (j = 0; j < old_size; j++)
	    tmp[j] = mem->pending[j];

	/* free the old list and set the new one */
	safe_free(mem->pending);
	mem->pending = tmp;

	debug(20, 9, "storeRegister: grew pending list to %d for slot %d.\n",
	    mem->pending_list_size, i);

    }
    mem->pending[i] = pe;
    return 0;
}

/* remove handler assoicate to that fd from store pending list */
/* Also remove entry from client_list if exist. */
/* return number of successfully free pending entries */
int storeUnregister(e, fd)
     StoreEntry *e;
     int fd;
{
    int i;
    int freed = 0;

    debug(20, 9, "storeUnregister: called for FD %d '%s'\n", fd, e->key);

    /* look for entry in client_list */
    if (e->mem_obj->client_list) {
	for (i = 0; i < e->mem_obj->client_list_size; ++i) {
	    if (e->mem_obj->client_list[i] && (e->mem_obj->client_list[i]->fd == fd)) {
		/* reset fd to zero as a mark for empty slot */
		safe_free(e->mem_obj->client_list[i]);
		e->mem_obj->client_list[i] = NULL;
	    }
	}
    }
    /* walk the entire list looking for matched fd */
    for (i = 0; i < (int) e->mem_obj->pending_list_size; i++) {
	if (e->mem_obj->pending[i] && (e->mem_obj->pending[i]->fd == fd)) {
	    /* found the match fd */
	    safe_free(e->mem_obj->pending[i]);
	    e->mem_obj->pending[i] = NULL;
	    freed++;
	}
    }

    debug(20, 9, "storeUnregister: returning %d\n", freed);
    return freed;
}

int storeGetLowestReaderOffset(entry)
     StoreEntry *entry;
{
    MemObject *mem = entry->mem_obj;
    int lowest = mem->e_current_len;
    int i;
    for (i = 0; i < mem->client_list_size; i++) {
	if (mem->client_list[i] == NULL)
	    continue;
	if (mem->client_list[i]->last_offset < lowest)
	    lowest = mem->client_list[i]->last_offset;
    }
    return lowest;
}

/* Call to delete behind upto "target lowest offset"
 * also, update e_lowest_offset  */
void storeDeleteBehind(e)
     StoreEntry *e;
{
    MemObject *mem = e->mem_obj;
    int free_up_to;
    int target_offset;

    debug(20, 3, "storeDeleteBehind: Object: %s\n", e->key);
    debug(20, 3, "storeDeleteBehind: Original Lowest Offset: %d\n",
	mem->e_lowest_offset);

    free_up_to = mem->e_lowest_offset;
    target_offset = storeGetLowestReaderOffset(e);

    debug(20, 3, "storeDeleteBehind: target offset: %d\n", target_offset);
    if (target_offset) {
	free_up_to = (int) mem->data->mem_free_data_upto(mem->data, target_offset);
	debug(20, 3, "--> Object is freed upto : %d\n", free_up_to);
	store_mem_size -= free_up_to - mem->e_lowest_offset;
    }
    debug(20, 3, "storeDeleteBehind: New lowest offset: %d\n", free_up_to);
    mem->e_lowest_offset = free_up_to;
}

/* Call handlers waiting for  data to be appended to E. */
static void InvokeHandlers(e)
     StoreEntry *e;
{
    int i;
    MemObject *mem = e->mem_obj;

    /* walk the entire list looking for valid handlers */
    for (i = 0; i < (int) mem->pending_list_size; i++) {
	if (mem->pending[i] && mem->pending[i]->handler) {
	    /* 
	     *  Once we call the handler, it is no longer needed 
	     *  until the write process sends all available data 
	     *  from the object entry. 
	     */
	    (mem->pending[i]->handler)
		(mem->pending[i]->fd, e, mem->pending[i]->data);
	    safe_free(mem->pending[i]);
	    mem->pending[i] = NULL;
	}
    }

}

/* Mark object as expired */
void storeExpireNow(e)
     StoreEntry *e;
{
    debug(20, 3, "storeExpireNow: '%s'\n", e->key);
    e->expires = squid_curtime;
}

/* switch object to deleting behind mode call by
 * retrieval module when object gets too big.  */
void storeStartDeleteBehind(e)
     StoreEntry *e;
{
    debug(20, 2, "storeStartDeleteBehind: Object: %s\n", e->key);
    if (e->flag & DELETE_BEHIND) {
	debug(20, 2, "storeStartDeleteBehind:\tis already in delete behind mode.\n");
	return;
    }
    debug(20, 2, "storeStartDeleteBehind:\tis now in delete behind mode.\n");
    /* change its key, so it couldn't be found by other client */
    storeSetPrivateKey(e);
    BIT_SET(e->flag, DELETE_BEHIND);
    storeReleaseRequest(e);
    BIT_RESET(e->flag, CACHABLE);
    storeExpireNow(e);
}

/* Append incoming data from a primary server to an entry. */
void storeAppend(e, data, len)
     StoreEntry *e;
     char *data;
     int len;
{
    /* validity check -- sometimes it's called with bogus values */
    if (e == NULL)
	fatal_dump("storeAppend: NULL entry.");
    if (e->mem_obj == NULL)
	fatal_dump("storeAppend: NULL entry->mem_obj");
    if (e->mem_obj->data == NULL)
	fatal_dump("storeAppend: NULL entry->mem_obj->data");

    if (len) {
	debug(20, 5, "storeAppend: appending %d bytes for '%s'\n", len, e->key);
	(void) storeGetMemSpace(len, 0);
	store_mem_size += len;
	(void) e->mem_obj->data->mem_append(e->mem_obj->data, data, len);
	e->mem_obj->e_current_len += len;
    }
    if (e->store_status != STORE_ABORTED && !(e->flag & DELAY_SENDING))
	InvokeHandlers(e);
}

#if defined(__STRICT_ANSI__)
void storeAppendPrintf(StoreEntry * e, char *fmt,...)
{
    va_list args;
    LOCAL_ARRAY(char, buf, 4096);
    va_start(args, fmt);
#else
void storeAppendPrintf(va_alist)
     va_dcl
{
    va_list args;
    StoreEntry *e = NULL;
    char *fmt = NULL;
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
int storeAddSwapDisk(path)
     char *path;
{
    if (cache_dirs == NULL)
	cache_dirs = create_dynamic_array(5, 5);
    /* XXX note xstrdup here prob means we
     * can't use destroy_dynamic_array() */
    insert_dynamic_array(cache_dirs, xstrdup(path));
    return ++ncache_dirs;
}

/* return the nth swap directory */
char *swappath(n)
     int n;
{
    return (char *) cache_dirs->collection[n % ncache_dirs];
}


/* return full name to swapfile */
char *storeSwapFullPath(fn, fullpath)
     int fn;
     char *fullpath;
{
    LOCAL_ARRAY(char, fullfilename, MAX_FILE_NAME_LEN);
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
int storeSwapInHandle(fd_notused, buf, len, flag, e, offset_notused)
     int fd_notused;
     char *buf;
     int len;
     int flag;
     StoreEntry *e;
     int offset_notused;
{
    MemObject *mem = e->mem_obj;
    debug(20, 2, "storeSwapInHandle: '%s'\n", e->key);

    if ((flag < 0) && (flag != DISK_EOF)) {
	debug(20, 0, "storeSwapInHandle: SwapIn failure (err code = %d).\n", flag);
	put_free_8k_page(mem->e_swap_buf);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	file_close(mem->swapin_fd);
	swapInError(-1, e);	/* Invokes storeAbort() and completes the I/O */
	if (mem->swapin_complete_handler) {
	    (*mem->swapin_complete_handler) (2, mem->swapin_complete_data);
	    mem->swapin_complete_handler = NULL;
	    mem->swapin_complete_data = NULL;
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
	debug(20, 5, "storeSwapInHandle: SwapIn complete: <URL:%s> from %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	if (mem->e_current_len != e->object_len) {
	    debug(20, 0, "storeSwapInHandle: WARNING! Object size mismatch.\n");
	    debug(20, 0, "  --> <URL:%s>\n", e->url);
	    debug(20, 0, "  --> Expecting %d bytes from file: %s\n", e->object_len,
		storeSwapFullPath(e->swap_file_number, NULL));
	    debug(20, 0, "  --> Only read %d bytes\n",
		mem->e_current_len);
	}
	if (mem->swapin_complete_handler) {
	    (*mem->swapin_complete_handler) (0, mem->swapin_complete_data);
	    mem->swapin_complete_handler = NULL;
	    mem->swapin_complete_data = NULL;
	}
	if (e->flag & RELEASE_REQUEST)
	    storeRelease(e);
    }
    return 0;
}

/* start swapping in */
static int storeSwapInStart(e, swapin_complete_handler, swapin_complete_data)
     StoreEntry *e;
     SIH swapin_complete_handler;
     void *swapin_complete_data;
{
    int fd;
    char *path = NULL;
    MemObject *mem = NULL;

    /* sanity check! */
    if ((e->swap_status != SWAP_OK) || (e->swap_file_number < 0)) {
	debug(20, 0, "storeSwapInStart: <No filename:%d> ? <URL:%s>\n",
	    e->swap_file_number, e->url);
	if (e->mem_obj)
	    e->mem_obj->swapin_fd = -1;
	return -1;
    }
    /* create additional structure for object in memory */
    e->mem_obj = mem = new_MemObject();

    path = storeSwapFullPath(e->swap_file_number, NULL);
    if ((fd = file_open(path, NULL, O_RDONLY)) < 0) {
	debug(20, 0, "storeSwapInStart: Failed for '%s'\n", e->url);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	/* Invoke a store abort that should free the memory object */
	return -1;
    }
    mem->swapin_fd = (short) fd;
    debug(20, 5, "storeSwapInStart: initialized swap file '%s' for <URL:%s>\n",
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

static void storeSwapLog(e)
     StoreEntry *e;
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

void storeSwapOutHandle(fd, flag, e)
     int fd;
     int flag;
     StoreEntry *e;
{
    LOCAL_ARRAY(char, filename, MAX_FILE_NAME_LEN);
    MemObject *mem = e->mem_obj;

    debug(20, 3, "storeSwapOutHandle: '%s'\n", e->key);

    e->timestamp = squid_curtime;
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
	    setCacheSwapMax(store_swap_size);
	    store_swap_high = (long) (((float) Config.Swap.maxSize *
		    (float) Config.Swap.highWaterMark) / (float) 100);
	    store_swap_low = (long) (((float) Config.Swap.maxSize *
		    (float) Config.Swap.lowWaterMark) / (float) 100);
	}
	return;
    }
    debug(20, 6, "storeSwapOutHandle: e->swap_offset    = %d\n",
	mem->swap_offset);
    debug(20, 6, "storeSwapOutHandle: e->e_swap_buf_len = %d\n",
	mem->e_swap_buf_len);
    debug(20, 6, "storeSwapOutHandle: e->object_len     = %d\n",
	e->object_len);
    debug(20, 6, "storeSwapOutHandle: store_swap_size   = %dk\n",
	store_swap_size);

    mem->swap_offset += mem->e_swap_buf_len;
    /* round up */
    store_swap_size += ((mem->e_swap_buf_len + 1023) >> 10);
    if (mem->swap_offset >= e->object_len) {
	/* swapping complete */
	e->swap_status = SWAP_OK;
	file_close(mem->swapout_fd);
	storeLog(STORE_LOG_SWAPOUT, e);
	debug(20, 5, "storeSwapOutHandle: SwapOut complete: <URL:%s> to %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	put_free_8k_page(mem->e_swap_buf);
	storeSwapLog(e);
	CacheInfo->proto_newobject(CacheInfo,
	    mem->request->protocol,
	    e->object_len,
	    FALSE);
	/* check if it's request to be released. */
	if (e->flag & RELEASE_REQUEST)
	    storeRelease(e);
	else if (storeCheckPurgeMem(e))
	    storePurgeMem(e);
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
static int storeSwapOutStart(e)
     StoreEntry *e;
{
    int fd;
    LOCAL_ARRAY(char, swapfilename, MAX_FILE_NAME_LEN);
    int x;
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
    debug(20, 5, "storeSwapOutStart: Begin SwapOut <URL:%s> to FD %d FILE %s.\n",
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
	&(mem->e_swap_buf_len));
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
static int storeDoRebuildFromDisk(data)
     struct storeRebuild_data *data;
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
    int delta;
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
		if (expires < squid_curtime) {
		    debug(20, 3, "storeRebuildFromDisk: Expired: <URL:%s>\n", url);
		    if (opt_unlink_on_reload)
			safeunlink(swapfile, 1);
		    data->expcount++;
		} else {
		    debug(20, 3, "storeRebuildFromDisk: Swap file missing: <URL:%s>: %s: %s.\n", url, swapfile, xstrerror());
		    if (opt_unlink_on_reload)
			safeunlink(swapfile, 1);
		}
		continue;
	    }
	    /* Empty swap file? */
	    if (sb.st_size == 0) {
		if (opt_unlink_on_reload)
		    safeunlink(swapfile, 1);
		continue;
	    }
	    /* timestamp might be a little bigger than sb.st_mtime */
	    delta = (int) (timestamp - sb.st_mtime);
	    if (delta > REBUILD_TIMESTAMP_DELTA_MAX || delta < 0) {
		/* this log entry doesn't correspond to this file */
		data->clashcount++;
		continue;
	    }
	    /* Wrong size? */
	    if (sb.st_size != size) {
		/* this log entry doesn't correspond to this file */
		data->clashcount++;
		continue;
	    }
	    timestamp = sb.st_mtime;
	    debug(20, 9, "storeRebuildFromDisk: swap file exists: <URL:%s>: %s\n",
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
	    debug(20, 6, "storeRebuildFromDisk: Duplicate: <URL:%s>\n", url);
	    storeRelease(e);
	    data->objcount--;
	    data->dupcount++;
	}
	if (expires < squid_curtime) {
	    debug(20, 3, "storeRebuildFromDisk: Expired: <URL:%s>\n", url);
	    if (opt_unlink_on_reload)
		safeunlink(swapfile, 1);
	    data->expcount++;
	    continue;
	}
	/* Is the swap file number already taken? */
	if (file_map_bit_test(sfileno)) {
	    /* Yes it is, we can't use this swapfile */
	    debug(20, 2, "storeRebuildFromDisk: Line %d Active clash: file #%d\n",
		data->linecount,
		sfileno);
	    debug(20, 3, "storeRebuildFromDisk: --> <URL:%s>\n", url);
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
	CacheInfo->proto_newobject(CacheInfo,
	    urlParseProtocol(url),
	    (int) size,
	    TRUE);
    }
    return 1;
}

/* meta data recreated from disk image in swap directory */
static void storeRebuiltFromDisk(data)
     struct storeRebuild_data *data;
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

void storeStartRebuildFromDisk()
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

    for (i = 0; i < ncache_dirs; ++i)
	debug(20, 1, "Rebuilding storage from disk image in %s\n", swappath(i));
    data->start = getCurrentTime();

    /* Check if log is clean */
    sprintf(tmp_filename, "%s/log-last-clean", swappath(0));
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
int storeGetSwapSize()
{
    return store_swap_size;
}

/* return current swap size in bytes */
int storeGetMemSize()
{
    return store_mem_size;
}

static int storeCheckSwapable(e)
     StoreEntry *e;
{

    if (e->expires <= squid_curtime) {
	debug(20, 2, "storeCheckSwapable: NO: already expired\n");
    } else if (e->method != METHOD_GET) {
	debug(20, 2, "storeCheckSwapable: NO: non-GET method\n");
    } else if (!BIT_TEST(e->flag, CACHABLE)) {
	debug(20, 2, "storeCheckSwapable: NO: not cachable\n");
    } else if (BIT_TEST(e->flag, RELEASE_REQUEST)) {
	debug(20, 2, "storeCheckSwapable: NO: release requested\n");
    } else if (!storeEntryValidLength(e)) {
	debug(20, 2, "storeCheckSwapable: NO: wrong content-length\n");
    } else
	return 1;

    storeReleaseRequest(e);
    BIT_RESET(e->flag, CACHABLE);
    return 0;
}



/* Complete transfer into the local cache.  */
void storeComplete(e)
     StoreEntry *e;
{
    debug(20, 3, "storeComplete: '%s'\n", e->key);

    e->object_len = e->mem_obj->e_current_len;
    InvokeHandlers(e);
    e->lastref = squid_curtime;
    e->store_status = STORE_OK;
    storeSetMemStatus(e, IN_MEMORY);
    e->swap_status = NO_SWAP;
    if (storeCheckSwapable(e))
	storeSwapOutStart(e);
    /* free up incoming MIME */
    safe_free(e->mem_obj->mime_hdr);
    if (e->flag & RELEASE_REQUEST)
	storeRelease(e);
}

/*
 * Fetch aborted.  Tell all clients to go home.  Negatively cache
 * abort message, freeing the data for this object 
 */
int storeAbort(e, msg)
     StoreEntry *e;
     char *msg;
{
    LOCAL_ARRAY(char, mime_hdr, 300);
    LOCAL_ARRAY(char, abort_msg, 2000);

    debug(20, 6, "storeAbort: '%s'\n", e->key);
    e->expires = squid_curtime + Config.negativeTtl;
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
    CacheInfo->proto_touchobject(CacheInfo,
	e->mem_obj->request->protocol,
	e->mem_obj->e_current_len);
    mk_mime_hdr(mime_hdr,
	(time_t) Config.negativeTtl,
	6 + strlen(msg),
	squid_curtime,
	"text/html");
    if (msg) {
	/* This can run off the end here. Be careful */
	if ((int) (strlen(msg) + strlen(mime_hdr) + 50) < 2000) {
	    sprintf(abort_msg, "HTTP/1.0 400 Cache Detected Error\r\n%s\r\n\r\n%s", mime_hdr, msg);
	} else {
	    debug(20, 0, "storeAbort: WARNING: Must increase msg length!");
	}
	storeAppend(e, abort_msg, strlen(abort_msg));
	e->mem_obj->e_abort_msg = xstrdup(abort_msg);
	/* Set up object for negative caching */
	BIT_SET(e->flag, ABORT_MSG_PENDING);
    }
    /* We assign an object length here--The only other place we assign the
     * object length is in storeComplete() */
    e->object_len = e->mem_obj->e_current_len;

    /* Call handlers so they can report error. */
    InvokeHandlers(e);

    storeUnlockObject(e);
    return 0;
}

/* get the first in memory object entry in the storage */
hash_link *storeFindFirst(id)
     HashID id;
{
    if (id == (HashID) 0)
	return NULL;
    return (hash_first(id));
}

/* get the next in memory object entry in the storage for a given
 * search pointer */
hash_link *storeFindNext(id)
     HashID id;
{
    if (id == (HashID) 0)
	return NULL;
    return (hash_next(id));
}

/* get the first in memory object entry in the storage */
StoreEntry *storeGetInMemFirst()
{
    hash_link *first = NULL;
    first = storeFindFirst(in_mem_table);
    return (first ? ((StoreEntry *) first->item) : NULL);
}


/* get the next in memory object entry in the storage for a given
 * search pointer */
StoreEntry *storeGetInMemNext()
{
    hash_link *next = NULL;
    next = storeFindNext(in_mem_table);
    return (next ? ((StoreEntry *) next->item) : NULL);
}

/* get the first entry in the storage */
StoreEntry *storeGetFirst()
{
    return ((StoreEntry *) storeFindFirst(store_table));
}


/* get the next entry in the storage for a given search pointer */
StoreEntry *storeGetNext()
{
    return ((StoreEntry *) storeFindNext(store_table));
}



/* walk through every single entry in the storage and invoke a given routine */
int storeWalkThrough(proc, data)
     int (*proc) _PARAMS((StoreEntry * e, void *data));
     void *data;
{
    StoreEntry *e = NULL;
    int count = 0;
    int n = 0;

    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if ((++n & 0xFF) == 0) {
	    getCurrentTime();
	    if (shutdown_pending || reread_pending)
		break;
	}
	if ((n & 0xFFF) == 0)
	    debug(20, 2, "storeWalkThrough: %7d objects so far.\n", n);
	count += proc(e, data);
    }
    return count;
}


/* compare an object timestamp and see if ttl is expired. Free it if so. */
/* return 1 if it expired, 0 if not */
int removeOldEntry(e, data)
     StoreEntry *e;
     void *data;
{
    time_t curtime = *((time_t *) data);

    debug(20, 5, "removeOldEntry: Checking: %s\n", e->url);
    debug(20, 6, "removeOldEntry:   *       curtime: %8ld\n", curtime);
    debug(20, 6, "removeOldEntry:   *  e->timestamp: %8ld\n", e->timestamp);
    debug(20, 6, "removeOldEntry:   * time in cache: %8ld\n",
	curtime - e->timestamp);
    debug(20, 6, "removeOldEntry:   *  time-to-live: %8ld\n",
	e->expires - squid_curtime);

    if ((squid_curtime > e->expires) && (e->store_status != STORE_PENDING)) {
	return (storeRelease(e) == 0 ? 1 : 0);
    }
    return 0;
}


/* free up all ttl-expired objects */
int storePurgeOld()
{
    int n;

    debug(20, 3, "storePurgeOld: Begin purging TTL-expired objects\n");
    n = storeWalkThrough(removeOldEntry, (void *) &squid_curtime);
    debug(20, 3, "storePurgeOld: Done purging TTL-expired objects.\n");
    debug(20, 3, "storePurgeOld: %d objects expired\n", n);
    return n;
}


#define MEM_LRUSCAN_BLOCK 16
#define MEM_MAX_HELP 5
/* Clear Memory storage to accommodate the given object len */
int storeGetMemSpace(size, check_vm_number)
     int size;
     int check_vm_number;
{
    static int over_highwater = 0;
    static int over_max = 0;
    StoreEntry *LRU = NULL, *e = NULL;
    dynamic_array *LRU_list = NULL;
    dynamic_array *pending_entry_list = NULL;
    int entry_to_delete_behind = 0;
    int n_deleted_behind = 0;
    int n_scanned = 0;
    int n_expired = 0;
    int n_aborted = 0;
    int n_purged = 0;
    int n_released = 0;
    int i;
    int n_inmem = 0;		/* extra debugging */
    int n_cantpurge = 0;	/* extra debugging */
    int mem_cantpurge = 0;	/* extra debugging */
    int compareLastRef();
    int compareSize();


    if (!check_vm_number && ((store_mem_size + size) < store_mem_high))
	return 0;

    debug(20, 2, "storeGetMemSpace: Starting...\n");

    LRU_list = create_dynamic_array(meta_data.store_in_mem_objects, MEM_LRUSCAN_BLOCK);
    pending_entry_list = create_dynamic_array(meta_data.store_in_mem_objects, MEM_LRUSCAN_BLOCK);

    for (e = storeGetInMemFirst(); e; e = storeGetInMemNext()) {
	n_scanned++;

	n_inmem++;

	if (e->store_status == STORE_PENDING) {
	    if (!(e->flag & DELETE_BEHIND)) {
		/* it's not deleting behind, we can do something about it. */
		insert_dynamic_array(pending_entry_list, e);
	    }
	    continue;
	}
	if (squid_curtime > e->expires) {
	    debug(20, 2, "storeGetMemSpace: Expired: %s\n", e->url);
	    n_expired++;
	    /* Delayed release */
	    storeRelease(e);
	    continue;
	}
	if ((e->swap_status == SWAP_OK) && (e->mem_status != SWAPPING_IN) &&
	    (e->lock_count == 0)) {
	    insert_dynamic_array(LRU_list, e);
	} else if (((e->store_status == STORE_ABORTED) ||
		    (e->swap_status == NO_SWAP)) &&
	    (e->lock_count == 0)) {
	    n_aborted++;
	    insert_dynamic_array(LRU_list, e);
	} else {
	    n_cantpurge++;
	    mem_cantpurge += e->mem_obj->e_current_len;
	    debug(20, 5, "storeGetMemSpace: Can't purge %7d bytes: %s\n",
		e->mem_obj->e_current_len, e->url);
	    if (e->swap_status != SWAP_OK)
		debug(20, 5, "storeGetMemSpace: --> e->swap_status != SWAP_OK\n");
	    if (e->lock_count)
		debug(20, 5, "storeGetMemSpace: --> e->lock_count %d\n", e->lock_count);
	}
    }
#ifdef EXTRA_DEBUGGING
    debug(20, 5, "storeGetMemSpace: Current size:     %7d bytes\n", store_mem_size);
    debug(20, 5, "storeGetMemSpace: High W Mark:      %7d bytes\n", store_mem_high);
    debug(20, 5, "storeGetMemSpace: Low W Mark:       %7d bytes\n", store_mem_low);
    debug(20, 5, "storeGetMemSpace: Entry count:      %7d items\n", meta_data.store_entries);
    debug(20, 5, "storeGetMemSpace: Scanned:          %7d items\n", n_scanned);
    debug(20, 5, "storeGetMemSpace: In memory:        %7d items\n", n_inmem);
    debug(20, 5, "storeGetMemSpace: Hot vm count:     %7d items\n", meta_data.hot_vm);
    debug(20, 5, "storeGetMemSpace: Expired:          %7d items\n", n_expired);
    debug(20, 5, "storeGetMemSpace: Negative Cached:  %7d items\n", n_aborted);
    debug(20, 5, "storeGetMemSpace: Can't purge:      %7d items\n", n_cantpurge);
    debug(20, 5, "storeGetMemSpace: Can't purge size: %7d bytes\n", mem_cantpurge);
    debug(20, 5, "storeGetMemSpace: Sorting LRU_list: %7d items\n", LRU_list->index);
#endif
    qsort((char *) LRU_list->collection, LRU_list->index, sizeof(e), (int (*)(const void *, const void *)) compareLastRef);

    /* Kick LRU out until we have enough memory space */

    if (check_vm_number) {
	/* look for vm slot */
	for (i = 0; (i < LRU_list->index) && (meta_data.hot_vm > store_hotobj_low); ++i) {
	    if ((LRU = (StoreEntry *) LRU_list->collection[i]))
		if ((LRU->store_status != STORE_PENDING) && (LRU->swap_status == NO_SWAP)) {
		    n_released++;
		    storeRelease(LRU);
		} else {
		    n_purged++;
		    storePurgeMem(LRU);
		}
	}
    } else {
	/* look for space */
	for (i = 0; (i < LRU_list->index) && ((store_mem_size + size) > store_mem_low); ++i) {
	    if ((LRU = (StoreEntry *) LRU_list->collection[i]))
		if ((LRU->store_status != STORE_PENDING) && (LRU->swap_status == NO_SWAP)) {
		    n_released++;
		    storeRelease(LRU);
		} else {
		    n_purged++;
		    storePurgeMem(LRU);
		}
	}
    }

    destroy_dynamic_array(LRU_list);

    debug(20, 2, "storeGetMemSpace: After freeing size: %7d bytes\n", store_mem_size);
    debug(20, 2, "storeGetMemSpace: Purged:             %7d items\n", n_purged);
    debug(20, 2, "storeGetMemSpace: Released:           %7d items\n", n_released);


    if (check_vm_number) {
	/* don't check for size */
	destroy_dynamic_array(pending_entry_list);
	debug(20, 2, "storeGetMemSpace: Done.\n");
	return 0;
    }
    if ((store_mem_size + size) < store_mem_high) {
	/* we don't care for hot_vm count here, just the storage size. */
	over_highwater = over_max = 0;
	destroy_dynamic_array(pending_entry_list);
	debug(20, 2, "storeGetMemSpace: Done.\n");
	return 0;
    }
    if ((store_mem_size + size) < Config.Mem.maxSize) {
	/* We're over high water mark here, but still under absolute max */
	if (!over_highwater) {
	    /* print only once when the condition occur until it clears. */
	    debug(20, 1, "storeGetMemSpace: Allocating beyond the high water mark with total size of %d\n",
		store_mem_size + size);
	    over_highwater = 1;
	}
	/* we can delete more than one if we want to be more aggressive. */
	entry_to_delete_behind = 1;
    } else {
	/* We're over absolute max */
	if (!over_max) {
	    /* print only once when the condition occur until it clears. */
	    debug(20, 1, "storeGetMemSpace: Allocating beyond the MAX Store with total size of %d\n",
		store_mem_size + size);
	    debug(20, 1, " Start Deleting Behind for every pending objects\n");
	    debug(20, 1, " You should really adjust your cache_mem, high/low water mark,\n");
	    debug(20, 1, " max object size to suit your need.\n");
	    over_max = 1;
	}
	/* delete all of them, we desperate for a space. */
	entry_to_delete_behind = pending_entry_list->index;
    }

    /* sort the stuff by size */
    qsort((char *) pending_entry_list->collection, pending_entry_list->index, sizeof(e), (int (*)(const void *, const void *)) compareSize);
    for (i = 0; (i < pending_entry_list->index) && (i < entry_to_delete_behind); ++i)
	if (pending_entry_list->collection[i]) {
	    n_deleted_behind++;
	    storeStartDeleteBehind(pending_entry_list->collection[i]);
	}
    if (n_deleted_behind) {
	debug(20, 1, "storeGetMemSpace: Due to memory flucuation, put %d objects to DELETE_BEHIND MODE.\n",
	    n_deleted_behind);
    }
    destroy_dynamic_array(pending_entry_list);
    debug(20, 2, "storeGetMemSpace: Done.\n");
    return 0;
}

int compareSize(e1, e2)
     StoreEntry **e1, **e2;
{
    if (!e1 || !e2) {
	debug(20, 1, "compareSize: Called with at least one null argument, shouldn't happen.\n");
	return 0;
    }
    if ((*e1)->mem_obj->e_current_len > (*e2)->mem_obj->e_current_len)
	return (1);

    if ((*e1)->mem_obj->e_current_len < (*e2)->mem_obj->e_current_len)
	return (-1);

    return (0);
}

int compareLastRef(e1, e2)
     StoreEntry **e1, **e2;
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
unsigned int storeGetBucketNum()
{
    static unsigned int bucket = 0;

    if (bucket >= STORE_BUCKETS)
	bucket = 0;
    return (bucket++);
}

#define SWAP_LRUSCAN_BLOCK 16
#define SWAP_MAX_HELP STORE_BUCKETS/2

/* The maximum objects to scan for maintain storage space */
#define SWAP_LRUSCAN_COUNT	(256)

/* Removes at most 30 LRU objects for one loop */
#define SWAP_LRU_REMOVE_COUNT	(8)

/* Clear Swap storage to accommodate the given object len */
int storeGetSwapSpace(size)
     int size;
{
    static int fReduceSwap = 0;
    static int swap_help = 0;
    StoreEntry *LRU = NULL, *e = NULL;
    int scanned = 0;
    int removed = 0;
    int expired = 0;
    int locked = 0;
    int locked_size = 0;
    int scan_in_objs = 0;
    int i;
    int LRU_cur_size = meta_data.store_entries;
    dynamic_array *LRU_list;
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

    LRU_list = create_dynamic_array(LRU_cur_size, LRU_cur_size);
    /* remove expired objects until recover enough space or no expired objects */
    for (i = 0; i < STORE_BUCKETS; ++i) {
	int expired_in_one_bucket = 0;

	link_ptr = hash_get_bucket(store_table, storeGetBucketNum());
	if (link_ptr == NULL)
	    continue;
	/* this while loop handles one bucket of hash table */
	expired_in_one_bucket = 0;
	while (link_ptr) {
	    scanned++;
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;

	    /* Identify objects that aren't locked, for replacement */
	    if ((e->store_status != STORE_PENDING) &&	/* We're still fetching the object */
		(e->swap_status == SWAP_OK) &&	/* Only release it if it is on disk */
		(e->lock_count == 0) &&		/* Be overly cautious */
		(e->mem_status != SWAPPING_IN)) {	/* Not if it's being faulted into memory */
		if (squid_curtime > e->expires) {
		    debug(20, 2, "storeGetSwapSpace: Expired: <URL:%s>\n", e->url);
		    /* just call release. don't have to check for lock status.
		     * storeRelease will take care of that and set a pending flag
		     * if it's still locked. */
		    ++expired_in_one_bucket;
		    storeRelease(e);
		} else {
		    /* Prepare to do LRU replacement */
		    insert_dynamic_array(LRU_list, e);
		    ++scan_in_objs;
		}
	    } else {
		debug(20, 2, "storeGetSwapSpace: Can't purge %7d bytes: <URL:%s>\n",
		    e->object_len, e->url);
		if (e->lock_count) {
		    debug(20, 2, "\t\te->lock_count %d\n", e->lock_count);
		}
		if (e->swap_status == SWAPPING_OUT) {
		    debug(20, 2, "\t\te->swap_status == SWAPPING_OUT\n");
		}
		locked++;
		locked_size += e->mem_obj->e_current_len;
	    }
	    link_ptr = next;
	}			/* while, end of one bucket of hash table */

	expired += expired_in_one_bucket;
	if (expired_in_one_bucket &&
	    ((!fReduceSwap && (store_swap_size + kb_size <= store_swap_high)) ||
		(fReduceSwap && (store_swap_size + kb_size <= store_swap_low)))
	    ) {
	    fReduceSwap = 0;
	    destroy_dynamic_array(LRU_list);
	    debug(20, 2, "storeGetSwapSpace: Finished, %d objects expired.\n",
		expired);
	    return 0;
	}
	qsort((char *) LRU_list->collection, LRU_list->index, sizeof(e), (int (*)(const void *, const void *)) compareLastRef);
	/* keep the first n LRU objects only */
	cut_dynamic_array(LRU_list, SWAP_LRU_REMOVE_COUNT);

	/* Scan in about SWAP_LRU_COUNT for one call */
	if (scan_in_objs >= SWAP_LRUSCAN_COUNT)
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

    /* Although all expired objects removed, still didn't recover enough */
    /* space.  Kick LRU out until we have enough swap space */
    for (i = 0; i < LRU_list->index; ++i) {
	if (store_swap_size + kb_size <= store_swap_low) {
	    fReduceSwap = 0;
	    break;
	}
	if ((LRU = LRU_list->collection[i]) != NULL) {
	    if (storeRelease(LRU) == 0) {
		removed++;
	    } else {
		debug(20, 2, "storeGetSwapSpace: Help! Can't remove objects. <%s>\n",
		    LRU->url);
	    }
	}
    }
    debug(20, 2, "storeGetSwapSpace: After Freeing Size:   %7d kbytes\n", store_swap_size);

    /* free the list */
    destroy_dynamic_array(LRU_list);

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
/* return 0 when success. */
int storeRelease(e)
     StoreEntry *e;
{
    StoreEntry *result = NULL;
    StoreEntry *head_result = NULL;
    hash_link *hptr = NULL;
    hash_link *head_table_entry = NULL;

    debug(20, 3, "storeRelease: Releasing: '%s'\n", e->key);

    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */
    if (storeEntryLocked(e)) {
	storeExpireNow(e);
	debug(20, 3, "storeRelease: Only setting RELEASE_REQUEST bit\n");
	storeReleaseRequest(e);
	return -1;
    }
    if (e->key != NULL) {
	if ((hptr = hash_lookup(store_table, e->key)) == NULL) {
	    debug(20, 0, "storeRelease: Not Found: '%s'\n", e->key);
	    debug(20, 0, "Dump of Entry 'e':\n %s\n", storeToString(e));
	    fatal_dump(NULL);
	}
	result = (StoreEntry *) hptr;
	if (result != e) {
	    debug(20, 0, "storeRelease: Duplicated entry? <URL:%s>\n",
		result->url ? result->url : "NULL");
	    debug(20, 0, "Dump of Entry 'e':\n%s", storeToString(e));
	    debug(20, 0, "Dump of Entry 'result':\n%s", storeToString(result));
	    fatal_dump(NULL);
	}
    }
    if (e->method == METHOD_GET) {
	/* check if coresponding HEAD object exists. */
	head_table_entry = hash_lookup(store_table,
	    storeGeneratePublicKey(e->url, METHOD_HEAD));
	if (head_table_entry) {
	    head_result = (StoreEntry *) head_table_entry;
	    if (head_result) {
		/* recursive call here to free up /head/ */
		storeRelease(head_result);
	    }
	}
    }
    if (store_rebuilding == STORE_REBUILDING_FAST) {
	debug(20, 2, "storeRelease: Delaying release until store is rebuilt: '%s'\n",
	    e->key ? e->key : e->url ? e->url : "NO URL");
	storeExpireNow(e);
	storeSetPrivateKey(e);
	return -1;
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
	CacheInfo->proto_purgeobject(CacheInfo,
	    urlParseProtocol(e->url),
	    e->object_len);
    }
    storeHashDelete(e);
    storeLog(STORE_LOG_RELEASE, e);
    destroy_StoreEntry(e);
    return 0;
}


/* return if the current key is the original one. */
int storeOriginalKey(e)
     StoreEntry *e;
{
    if (!e)
	return 1;
    return !(e->flag & KEY_CHANGE);
}

/* return 1 if a store entry is locked */
int storeEntryLocked(e)
     StoreEntry *e;
{
    if (!e) {
	debug(20, 0, "This entry should be valid.\n");
	debug(20, 0, "%s", storeToString(e));
	fatal_dump(NULL);
    }
    if (e->lock_count)
	return 1;
    if (e->swap_status == SWAPPING_OUT)
	return 1;
    if (e->mem_status == SWAPPING_IN)
	return 1;
    return 0;
}

/*  use this for internal call only */
int storeCopy(e, stateoffset, maxSize, buf, size)
     StoreEntry *e;
     int stateoffset;
     int maxSize;
     char *buf;
     int *size;
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
int storeClientWaiting(e)
     StoreEntry *e;
{
    int i;

    if (e->mem_obj->client_list) {
	for (i = 0; i < e->mem_obj->client_list_size; ++i) {
	    if (e->mem_obj->client_list[i])
		return 1;
	}
    }
    if (e->mem_obj->pending) {
	for (i = 0; i < (int) e->mem_obj->pending_list_size; ++i) {
	    if (e->mem_obj->pending[i])
		return 1;
	}
    }
    return 0;
}

/* return index to matched clientstatus in client_list, -1 on NOT_FOUND */
int storeClientListSearch(e, fd)
     StoreEntry *e;
     int fd;
{
    int i;

    if (!e->mem_obj->client_list)
	return -1;
    for (i = 0; i < e->mem_obj->client_list_size; ++i) {
	if (e->mem_obj->client_list[i] &&
	    (fd == e->mem_obj->client_list[i]->fd))
	    return i;
    }
    return -1;
}

/* add client with fd to client list */
void storeClientListAdd(e, fd, last_offset)
     StoreEntry *e;
     int fd;
     int last_offset;
{
    int i;
    /* look for empty slot */

    if (e->mem_obj->client_list) {
	for (i = 0; (i < e->mem_obj->client_list_size)
	    && (e->mem_obj->client_list[i] != NULL); ++i);

	if (i == e->mem_obj->client_list_size) {
	    /* have to expand client_list */
	    e->mem_obj->client_list_size += MIN_CLIENT;
	    e->mem_obj->client_list = xrealloc(e->mem_obj->client_list, e->mem_obj->client_list_size * sizeof(ClientStatusEntry *));
	}
    } else {
	e->mem_obj->client_list_size += MIN_CLIENT;
	e->mem_obj->client_list = xcalloc(e->mem_obj->client_list_size, sizeof(ClientStatusEntry *));
	i = 0;
    }

    e->mem_obj->client_list[i] = xcalloc(1, sizeof(ClientStatusEntry));
    e->mem_obj->client_list[i]->fd = fd;
    e->mem_obj->client_list[i]->last_offset = last_offset;
}

/* same to storeCopy but also register client fd and last requested offset
 * for each client */
int storeClientCopy(e, stateoffset, maxSize, buf, size, fd)
     StoreEntry *e;
     int stateoffset;
     int maxSize;
     char *buf;
     int *size;
     int fd;
{
    int next_offset;
    int client_list_index;
    int available_to_write = e->mem_obj->e_current_len - stateoffset;

    if (stateoffset < e->mem_obj->e_lowest_offset) {
	/* this should not happen. Logic race !!! */
	debug(20, 1, "storeClientCopy: Client Request a chunk of data in area lower than the lowest_offset\n");
	debug(20, 1, "                              fd : %d\n", fd);
	debug(20, 1, "           Current Lowest offset : %d\n", e->mem_obj->e_lowest_offset);
	debug(20, 1, "           Requested offset      : %d\n", stateoffset);
	/* can't really do anything here. Client may hang until lifetime runout. */
	return 0;
    }
    *size = (available_to_write >= maxSize) ?
	maxSize : available_to_write;

    debug(20, 6, "storeCopy: avail_to_write=%d, store_offset=%d\n",
	*size, stateoffset);

    /* update the lowest requested offset */
    next_offset = (stateoffset + *size);
    if ((client_list_index = storeClientListSearch(e, fd)) >= 0) {
	e->mem_obj->client_list[client_list_index]->last_offset = next_offset;
    } else {
	storeClientListAdd(e, fd, next_offset);
    }

    if (*size > 0)
	(void) e->mem_obj->data->mem_copy(e->mem_obj->data, stateoffset, buf, *size);

    /* see if we can get rid of some data if we are in "delete behind" mode . */
    if (e->flag & DELETE_BEHIND) {
	/* call the handler to delete behind the lowest offset */
	storeDeleteBehind(e);
    }
    return *size;
}


int storeEntryValidToSend(e)
     StoreEntry *e;
{
    /* XXX I think this is not needed since storeCheckPurgeMem() has
     * been added.  If we never see output from this, lets delete it
     * in a future version -DW */
    if ((e->mem_status == NOT_IN_MEMORY) &&	/* Not in memory */
	(e->swap_status != SWAP_OK) &&	/* Not on disk */
	(e->store_status != STORE_PENDING)	/* Not being fetched */
	) {
	debug(20, 0, "storeEntryValidToSend: Invalid object detected!\n");
	debug(20, 0, "storeEntryValidToSend: Entry Dump:\n%s\n", storeToString(e));
	return 0;
    }
    if (squid_curtime < e->expires)
	return 1;
    if (e->expires == 0 && e->store_status == STORE_PENDING && e->mem_status != NOT_IN_MEMORY)
	return 1;
    return 0;
}

int storeEntryValidLength(e)
     StoreEntry *e;
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

static int storeVerifySwapDirs(clean)
     int clean;
{
    int inx;
    char *path = NULL;
    struct stat sb;
    int directory_created = 0;
    char *cmdbuf = NULL;

    for (inx = 0; inx < ncache_dirs; ++inx) {
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

static void storeCreateSwapSubDirs()
{
    int i, j, k;
    LOCAL_ARRAY(char, name, MAXPATHLEN);
    for (j = 0; j < ncache_dirs; j++) {
	for (i = 0; i < SWAP_DIRECTORIES_L1; i++) {
	    sprintf(name, "%s/%02X", swappath(j), i);
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

int storeInit()
{
    int dir_created;
    wordlist *w = NULL;
    char *fname = NULL;

    if (strcmp((fname = Config.Log.store), "none") == 0)
	storelog_fd = -1;
    else
	storelog_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (storelog_fd < 0)
	debug(20, 1, "Store logging disabled\n");

    for (w = Config.cache_dirs; w; w = w->next)
	storeAddSwapDisk(w->key);
    storeSanityCheck();
    file_map_create(MAX_SWAP_FILE);
    dir_created = storeVerifySwapDirs(opt_zap_disk_store);
    storeCreateHashTable(urlcmp);

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

    store_mem_high = (long) (Config.Mem.maxSize / 100) *
	Config.Mem.highWaterMark;
    store_mem_low = (long) (Config.Mem.maxSize / 100) *
	Config.Mem.lowWaterMark;

    store_hotobj_high = (int) (Config.hotVmFactor *
	store_mem_high / (1 << 20));
    store_hotobj_low = (int) (Config.hotVmFactor *
	store_mem_low / (1 << 20));

    /* check for validity */
    if (store_hotobj_low > store_hotobj_high)
	store_hotobj_low = store_hotobj_high;

    store_swap_high = (long) (Config.Swap.maxSize / 100) *
	Config.Swap.highWaterMark;
    store_swap_low = (long) (Config.Swap.maxSize / 100) *
	Config.Swap.lowWaterMark;

    return 0;
}

/* 
 *  storeSanityCheck - verify that all swap storage areas exist, and
 *  are writable; otherwise, force -z.
 */
void storeSanityCheck()
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

int urlcmp(url1, url2)
     char *url1, *url2;
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
int storeMaintainSwapSpace()
{
    static time_t last_time = 0;
    static unsigned int bucket = 0;
    hash_link *link_ptr = NULL, *next = NULL;
    StoreEntry *e = NULL;
    int rm_obj = 0;

    /* We can't delete objects while rebuilding swap */
    if (store_rebuilding == STORE_REBUILDING_FAST)
	return -1;

    /* Scan row of hash table each second and free storage if we're
     * over the high-water mark */
    storeGetSwapSpace(0);

    /* Purges expired objects, check one bucket on each calling */
    if (squid_curtime - last_time >= STORE_MAINTAIN_RATE) {
	last_time = squid_curtime;
	if (bucket >= STORE_BUCKETS)
	    bucket = 0;
	link_ptr = hash_get_bucket(store_table, bucket++);
	while (link_ptr) {
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;
	    if ((squid_curtime > e->expires) &&
		(e->swap_status == SWAP_OK)) {
		debug(20, 2, "storeMaintainSwapSpace: Expired: <TTL:%d> <URL:%s>\n",
		    e->expires - squid_curtime, e->url);
		/* just call release. don't have to check for lock status.
		 * storeRelease will take care of that and set a pending flag
		 * if it's still locked. */
		storeRelease(e);
		++rm_obj;
	    }
	    link_ptr = next;
	}
    }
    debug(20, rm_obj ? 2 : 3, "Removed %d expired objects\n", rm_obj);
    return rm_obj;
}


/*
 *  storeWriteCleanLog
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
int storeWriteCleanLog()
{
    StoreEntry *e = NULL;
    LOCAL_ARRAY(char, swapfilename, MAX_FILE_NAME_LEN);
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
    sprintf(tmp_filename, "%s/log_clean", swappath(0));
    if ((fp = fopen(tmp_filename, "a+")) == NULL) {
	debug(20, 0, "storeWriteCleanLog: %s: %s", tmp_filename, xstrerror());
	return 0;
    }
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	debug(20, 5, "storeWriteCleanLog: <URL:%s>\n", e->url);
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAP_OK)
	    continue;
	if (e->object_len <= 0)
	    continue;
	storeSwapFullPath(e->swap_file_number, swapfilename);
	x = fprintf(fp, "%08x %08x %08x %08x %9d %s\n",
	    (int) e->swap_file_number,
	    (int) e->timestamp,
	    (int) e->expires,
	    (int) e->lastmod,
	    e->object_len,
	    e->url);
	if (x < 0) {
	    debug(20, 0, "storeWriteCleanLog: %s: %s", tmp_filename, xstrerror());
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
	debug(20, 0, "storeWriteCleanLog: %s: %s", tmp_filename, xstrerror());
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
    sprintf(tmp_filename, "%s/log-last-clean", swappath(0));
    file_close(file_open(tmp_filename, NULL, O_WRONLY | O_CREAT | O_TRUNC));
    return n;
}

int swapInError(fd_unused, entry)
     int fd_unused;
     StoreEntry *entry;
{
    squid_error_entry(entry, ERR_DISK_IO, xstrerror());
    return 0;
}

int storePendingNClients(e)
     StoreEntry *e;
{
    int npend = 0;
    int i;

    if (!e->mem_obj)
	return 0;
    for (npend = i = 0; i < (int) e->mem_obj->pending_list_size; i++) {
	if (e->mem_obj->pending[i])
	    npend++;
    }
    return npend;
}

void storeRotateLog()
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

/*
 * Check if its okay to remove the memory data for this object, but 
 * leave the StoreEntry around.  Designed to be called from
 * storeUnlockObject() and storeSwapOutHandle().
 */
static int storeCheckPurgeMem(e)
     StoreEntry *e;
{
    if (storeEntryLocked(e))
	return 0;
    if (e->store_status != STORE_OK)
	return 0;
    if (store_hotobj_high)
	return 0;
    return 1;
}
