
/* $Id: store.cc,v 1.7 1996/03/25 19:05:52 wessels Exp $ */

/* 
 * Here is a summary of the routines which change mem_status and swap_status:
 * Added 11/18/95
 * 
 * Routine                  mem_status      swap_status         status 
 * ---------------------------------------------------------------------------
 * storeAdd                 NOT_IN_MEMORY   NO_SWAP
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

#include "config.h"		/* goes first */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>

#include "ansihelp.h"		/* goes secound */
#include "comm.h"
#include "proto.h"
#include "url.h"
#include "stat.h"
#include "disk.h"
#include "store.h"
#include "cache_cf.h"
#include "hash.h"
#include "debug.h"
#include "dynamic_array.h"
#include "util.h"
#include "filemap.h"
#include "stmem.h"
#include "mime.h"
#include "cached_error.h"

extern time_t cached_curtime;
extern char *storeToString _PARAMS((StoreEntry * e));
extern int proto_url_to_id _PARAMS((char *url));
extern int file_write_lock _PARAMS((int));
extern void fatal_dump _PARAMS((char *));
extern void fatal _PARAMS((char *));
extern void death();
char *tmp_error_buf;

#define REBUILD_TIMESTAMP_DELTA_MAX 2
#define MAX_SWAP_FILE		(1<<21)
#define SWAP_BUF		DISK_PAGE_SIZE
#define FATAL_BUF_SIZE		1024
#define SWAP_DIRECTORIES	100
#ifndef DEFAULT_SWAP_DIR
#define DEFAULT_SWAP_DIR	"/tmp/cache"
#endif

/* rate of checking expired objects in main loop */
#define STORE_MAINTAIN_RATE	(20)

#define STORE_BUCKETS		(7921)
#define STORE_IN_MEM_BUCKETS	(143)

int urlcmp _PARAMS((char *s1, char *s2));
int safeunlink _PARAMS((char *, int));
int swapInError _PARAMS((int fd_unused, StoreEntry * entry));
int storeSwapInStart _PARAMS((StoreEntry * e));
int storeCopy _PARAMS((StoreEntry * e, int stateoffset, int maxSize, char *buf, int *size));

/* Now, this table is inaccessible to outsider. They have to use a method
 * to access a value in internal storage data structure. */
HashID table = 0;
/* hash table for in-memory-only objects */
HashID in_mem_table = 0;

/* initializtion flag */
static int ok_write_clean_log = 0;

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
static int swaplog_fd = 0;
static int swaplog_lock;
static int swaplog_tmp_fd = 0;
FILE *swaplog_stream = NULL;
FILE *swaplog_tmp_stream = NULL;

/* counter for uncachable objects */
static int uncache_count = 0;
static int keychange_count = 0;

/* key temp buffer */
static char key_temp_buffer[MAX_URL];

/* patch cache_dir to accomodate multiple disk storage */
dynamic_array *cache_dirs = NULL;
int ncache_dirs = 0;

/* Allocate memory for a new store structure */
StoreEntry *create_StoreEntry()
{
    StoreEntry *e = NULL;

    e = (StoreEntry *) xcalloc(1, sizeof(StoreEntry));
    e->mem_obj = (MemObject *) xcalloc(1, sizeof(MemObject));
    meta_data.store_in_mem_objects++;

    return (e);
}

StoreEntry *create_StoreEntry_only()
{
    return ((StoreEntry *) xcalloc(1, sizeof(StoreEntry)));
}

/* Free memory of a store structure */
/* free a StoreEntry */
void destroy_StoreEntry(e)
     StoreEntry *e;
{
    if (e) {
	if (e->mem_obj) {
	    meta_data.store_in_mem_objects--;
	    xfree(e->mem_obj);
	}
	safe_free(e);
    }
}


/* free unused memory while object is not in memory */
void destroy_store_mem_obj(e)
     StoreEntry *e;
{
    if (e && e->mem_obj) {
	safe_free(e->mem_obj->mime_hdr);
	safe_free(e->mem_obj);
	meta_data.store_in_mem_objects--;
    }
}

/* Check if there is memory allocated for object in memory */
int has_mem_obj(e)
     StoreEntry *e;
{
    if (e && e->mem_obj)
	return (TRUE);
    return (FALSE);
}

/* allocate memory for swapping object in memory */
void create_store_mem_obj(e)
     StoreEntry *e;
{
    if (e) {
	if (has_mem_obj(e))
	    debug(1, "create_store_mem_obj: old memory not released\n");
	e->mem_obj = (MemObject *) xcalloc(1, sizeof(MemObject));
	meta_data.store_in_mem_objects++;
    }
}

/* ----- INTERFACE BETWEEN STORAGE MANAGER AND HASH TABLE FUNCTIONS --------- */

/*
 * Create 2 hash tables, "table" has all objects, "in_mem_table" has only
 * objects in the memory.
 */

HashID storeCreateHashTable(cmp_func)
     int (*cmp_func) (char *, char *);
{
    table = hash_create(cmp_func, STORE_BUCKETS);
    in_mem_table = hash_create(cmp_func, STORE_IN_MEM_BUCKETS);
    return (table);
}

/*
 * if object is in memory, also insert into in_mem_table
 */

int storeHashInsert(e)
     StoreEntry *e;
{
    if (e->mem_status == IN_MEMORY)
	hash_insert(in_mem_table, e->key, e);
    return (hash_join(table, (hash_link *) e));
}

/*
 * if object in memory, also remove from in_mem_table
 */

int storeHashDelete(hash_ptr)
     hash_link *hash_ptr;
{
    hash_link *hptr = NULL;
    StoreEntry *e = NULL;

    e = (StoreEntry *) hash_ptr;
    if (e->mem_status == IN_MEMORY && e->key) {
	if ((hptr = hash_lookup(in_mem_table, e->key)))
	    hash_delete_link(in_mem_table, hptr);
    }
    return (hash_remove_link(table, hash_ptr));
}

/*
 * maintain the in-mem hash table according to the changes of mem_status
 * This routine replaces the instruction "e->status = status;"
 */

void storeSetMemStatus(e, status)
     StoreEntry *e;
     int status;
{
    hash_link *ptr = NULL;

    if (e->mem_status == IN_MEMORY && status != IN_MEMORY) {
	if (e->key == NULL) {
	    debug(0, "storeSetMemStatus: NULL key for %s\n", e->url);
	    return;
	}
	if ((ptr = hash_lookup(in_mem_table, e->key)))
	    hash_delete_link(in_mem_table, ptr);
    } else if (status == IN_MEMORY && e->mem_status != IN_MEMORY) {
	hash_insert(in_mem_table, e->key, e);
    }
    e->mem_status = status;
}

/* -------------------------------------------------------------------------- */

/* free whole entry */
void storeFreeEntry(e)
     StoreEntry *e;
{
    meta_data.store_entries--;

    if (e == (StoreEntry *) NULL)
	return;

    debug(5, "storeFreeEntry: Freeing %s\n", e->url);

    if (has_mem_obj(e)) {
	store_mem_size -= e->mem_obj->e_current_len - e->mem_obj->e_lowest_offset;
	debug(8, "storeFreeEntry: Freeing %d in-memory bytes\n",
	    e->mem_obj->e_current_len);
	debug(8, "storeFreeEntry: store_mem_size = %d\n", store_mem_size);
	if (e->mem_obj->data) {
	    e->mem_obj->data->mem_free(e->mem_obj->data);
	    e->mem_obj->data = NULL;
	    --meta_data.hot_vm;
	}
    }
    meta_data.url_strings -= strlen(e->url);
    safe_free(e->url);
    if (!(e->flag & KEY_URL))
	safe_free(e->key);
    if (has_mem_obj(e)) {
	safe_free(e->mem_obj->mime_hdr);
	/* Leave an unzeroed pointer to the abort msg for posterity */
	if (e->mem_obj->e_abort_msg)
	    free(e->mem_obj->e_abort_msg);
	safe_free(e->mem_obj->pending);
	/* look up to free client_list */
	if (e->mem_obj->client_list) {
	    int i;
	    for (i = 0; i < e->mem_obj->client_list_size; ++i) {
		if (e->mem_obj->client_list[i])
		    safe_free(e->mem_obj->client_list[i]);
	    }
	    safe_free(e->mem_obj->client_list);
	}
    }
    destroy_StoreEntry(e);
}

/* free only data buffer, let the rest of structure stay. 
 * For Negative cache purpose. */
void storeFreeEntryData(e)
     StoreEntry *e;
{
    debug(5, "storeFreeEntryData: Freeing data-buffer only %s\n", e->url);
    store_mem_size -= e->mem_obj->e_current_len - e->mem_obj->e_lowest_offset;
    debug(8, "storeFreeEntryData: Freeing %d in-memory bytes\n",
	e->mem_obj->e_current_len);
    debug(8, "storeFreeEntryData: store_mem_size = %d\n", store_mem_size);
    e->object_len = 0;
    e->mem_obj->e_current_len = 0;
    if (e->mem_obj->data) {
	e->mem_obj->data->mem_free(e->mem_obj->data);
	e->mem_obj->data = NULL;
    }
}


/* get rid of memory copy of the object */
void storePurgeMem(e)
     StoreEntry *e;
{
    debug(5, "storePurgeMem: Freeing memory-copy of %s\n", e->url);
    if (!has_mem_obj(e))
	return;

    if (storeEntryLocked(e)) {
	debug(0, "storePurgeMem: someone (storeGetMemSpace?) is purging a locked object?\n");
	debug(0, "%s", storeToString(e));
	fatal_dump(NULL);
    }
    /* free up memory data */
    if (e->mem_obj->data) {
	e->mem_obj->data->mem_free(e->mem_obj->data);
	e->mem_obj->data = NULL;
	--meta_data.hot_vm;
    }
    store_mem_size -= e->object_len - e->mem_obj->e_lowest_offset;
    debug(8, "storePurgeMem: Freeing %d in-memory bytes\n",
	e->object_len);
    debug(8, "storePurgeMem: store_mem_size = %d\n", store_mem_size);
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->mem_obj->e_current_len = 0;
    /* free up pending list table */
    safe_free(e->mem_obj->pending);
    e->mem_obj->pending_list_size = 0;
    /* free up client list table and entries */
    if (e->mem_obj->client_list) {
	int i;
	for (i = 0; i < e->mem_obj->client_list_size; ++i) {
	    if (e->mem_obj->client_list[i])
		safe_free(e->mem_obj->client_list[i]);
	}
	safe_free(e->mem_obj->client_list);
    }
    destroy_store_mem_obj(e);
}

/* lock the object for reading, start swapping in if necessary */
int storeLockObject(e)
     StoreEntry *e;
{
    int swap_in_stat = 0;
    int status = 0;

    e->lock_count++;
    debug(5, "storeLockObject: locks %d: <URL:%s>\n", e->lock_count, e->url);

    if ((e->mem_status == NOT_IN_MEMORY) &&	/* Not in memory */
	(e->swap_status != SWAP_OK) &&	/* Not on disk */
	(e->status != STORE_PENDING)	/* Not being fetched */
	) {
	debug(0, "storeLockObject: NOT_IN_MEMORY && !SWAP_OK && !STORE_PENDING conflict: <URL:%s>. aborting...\n", e->url);
	/* If this sanity check fails, we should just ... */
	fatal_dump(NULL);
    }
    e->lastref = cached_curtime;

    /* StoreLockObject() is called during icp_hit_or_miss and once by storeAbort 
     * If the object is NOT_IN_MEMORY, fault it in. */
    if ((e->mem_status == NOT_IN_MEMORY) && (e->swap_status == SWAP_OK)) {
	/* object is in disk and no swapping daemon running. Bring it in. */
	if ((swap_in_stat = storeSwapInStart(e)) < 0) {
	    /*
	     * We couldn't find or couldn't open object's swapfile.
	     * So, return a -1 here, indicating that we will treat
	     * the reference like a MISS_TTL, force a keychange and
	     storeRelease.  */
	    e->lock_count--;
	}
	status = swap_in_stat;
    }
    return status;
}

/* unlock object, return -1 if object get released after unlock
 * otherwise lock_count */

int storeUnlockObject(e)
     StoreEntry *e;
{
    int e_lock_count;

    if ((int) e->lock_count > 0)
	e->lock_count--;
    else if (e->lock_count == 0) {
	debug(0, "Entry lock count %d is out-of-whack\n", e->lock_count);
    }
    /* Prevent UMR if we end up freeing the entry */
    e_lock_count = (int) e->lock_count;

    if (e->lock_count == 0) {

	if (e->flag & RELEASE_REQUEST) {
	    storeRelease(e);
	} else if (e->flag & ABORT_MSG_PENDING) {
	    /* This is where the negative cache gets storeAppended */
	    /* Briefly lock to replace content with abort message */
	    e->lock_count++;
	    storeFreeEntryData(e);
	    e->mem_obj->data = memInit();
	    storeAppend(e, e->mem_obj->e_abort_msg, strlen(e->mem_obj->e_abort_msg));
	    e->object_len = e->mem_obj->e_current_len
		= strlen(e->mem_obj->e_abort_msg);
	    BIT_RESET(e->flag, ABORT_MSG_PENDING);
	    e->lock_count--;
	}
    }
    return e_lock_count;

}

/* Lookup an object in the cache. 
 * return just a reference to object, don't start swapping in yet. */
StoreEntry *storeGet(url)
     char *url;
{
    hash_link *hptr = NULL;

    debug(5, "storeGet: looking up %s\n", url);

    if (table != (HashID) 0) {
	if ((hptr = hash_lookup(table, url)) != NULL)
	    return (StoreEntry *) hptr;
    }
    return NULL;
}

char *storeGenerateKey(url, request_type_id)
     char *url;
     int request_type_id;
{
    debug(5, "storeGenerateKey: type=%d %s\n", request_type_id, url);
    if (request_type_id == REQUEST_OP_POST) {
	sprintf(key_temp_buffer, "/post/%s", url);
	return key_temp_buffer;
    }
    if (request_type_id == REQUEST_OP_HEAD) {
	sprintf(key_temp_buffer, "/head/%s", url);
	return key_temp_buffer;
    }
    return url;
}

/* Add a new object to the cache. */
StoreEntry *storeAdd(url, type_notused, mime_hdr, cachable, html_request, request_type_id)
     char *url;
     char *type_notused;
     char *mime_hdr;
     int cachable;
     int html_request;
     int request_type_id;
{
    char key[MAX_URL + 16];
    StoreEntry *e = NULL;

    debug(5, "storeAdd: %s\n", url);

    meta_data.store_entries++;
    meta_data.url_strings += strlen(url);

    if (meta_data.hot_vm > store_hotobj_high)
	storeGetMemSpace(0, 1);
    e = create_StoreEntry();
    e->url = xstrdup(url);
    e->key = NULL;
    e->flag = 0;
    e->type_id = request_type_id;
    if (mime_hdr) {
	e->mem_obj->mime_hdr = xstrdup(mime_hdr);
	if (mime_refresh_request(mime_hdr))
	    BIT_SET(e->flag, REFRESH_REQUEST);
	else
	    BIT_RESET(e->flag, REFRESH_REQUEST);
    }
    if (cachable) {
	BIT_SET(e->flag, CACHABLE);
	BIT_RESET(e->flag, RELEASE_REQUEST);
    } else {
	BIT_RESET(e->flag, CACHABLE);
	/*after a lock is release, it will be released by storeUnlock */
	BIT_SET(e->flag, RELEASE_REQUEST);
    }

    if (html_request)
	BIT_SET(e->flag, REQ_HTML);
    else
	BIT_RESET(e->flag, REQ_HTML);

    e->status = STORE_PENDING;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = NO_SWAP;
    e->swap_file_number = -1;
    e->lock_count = 0;
    BIT_RESET(e->flag, KEY_CHANGE);
    BIT_RESET(e->flag, CLIENT_ABORT_REQUEST);
    e->mem_obj->data = memInit();
    meta_data.hot_vm++;
    e->refcount = 0;
    e->lastref = cached_curtime;
    e->timestamp = 0;		/* set in storeSwapOutHandle() */
    e->ping_status = NOPING;
    if (e->flag & CACHABLE) {
	if (request_type_id == REQUEST_OP_GET) {
	    e->key = e->url;
	    BIT_SET(e->flag, KEY_URL);
	} else {
	    e->key = xstrdup(storeGenerateKey(e->url, request_type_id));
	    BIT_RESET(e->flag, KEY_URL);
	}
    } else {
	/* prepend a uncache count number to url for a key */
	key[0] = '\0';
	sprintf(key, "/%d/%s", uncache_count, url);
	uncache_count++;
	e->key = xstrdup(key);
	BIT_RESET(e->flag, KEY_URL);
    }

    /* allocate pending list */
    e->mem_obj->pending_list_size = MIN_PENDING;
    e->mem_obj->pending = (struct pentry **)
	xcalloc(e->mem_obj->pending_list_size, sizeof(struct pentry *));

    /* allocate client list */
    e->mem_obj->client_list_size = MIN_CLIENT;
    e->mem_obj->client_list = (ClientStatusEntry **)
	xcalloc(e->mem_obj->client_list_size, sizeof(ClientStatusEntry *));

    if (table == (HashID) 0) {
	storeCreateHashTable(urlcmp);
    }
    storeHashInsert(e);
    return e;
}

/* Add a new object to the cache with empty memory copy and pointer to disk
 * use to rebuild store from disk. */
StoreEntry *storeAddDiskRestore(url, file_number, size, expires, timestamp)
     char *url;
     int file_number;
     int size;
     time_t expires;
     time_t timestamp;
{
    StoreEntry *e = NULL;

    debug(5, "StoreAddDiskRestore: <URL:%s>: size %d: expires %d: file_number %d\n",
	url, size, expires, file_number);

    if (file_map_bit_test(file_number)) {
	debug(0, "This file number is already allocated!\n");
	debug(0, "    --> file_number %d\n", file_number);
	debug(0, "    --> <URL:%s>\n", url);
	return (NULL);
    }
    meta_data.store_entries++;
    meta_data.url_strings += strlen(url);

    e = create_StoreEntry_only();
    e->url = xstrdup(url);
    e->key = NULL;
    e->flag = 0;
    e->type_id = REQUEST_OP_GET;
    BIT_SET(e->flag, CACHABLE);
    BIT_RESET(e->flag, RELEASE_REQUEST);
    BIT_SET(e->flag, REQ_HTML);
    e->status = STORE_OK;
    storeSetMemStatus(e, NOT_IN_MEMORY);
    e->swap_status = SWAP_OK;
    e->swap_file_number = file_number;
    file_map_bit_set(file_number);
    e->object_len = size;
    e->lock_count = 0;
    BIT_RESET(e->flag, KEY_CHANGE);
    BIT_RESET(e->flag, CLIENT_ABORT_REQUEST);
    e->refcount = 0;
    e->lastref = cached_curtime;
    e->timestamp = (u_num32) timestamp;
    e->expires = (u_num32) expires;
    e->ping_status = NOPING;

    e->key = e->url;
    BIT_SET(e->flag, KEY_URL);

    if (!table) {
	storeCreateHashTable(urlcmp);
    }
    storeHashInsert(e);
    return e;
}

/* Register interest in an object currently being retrieved. */
int storeRegister(e, fd, handler, data)
     StoreEntry *e;
     int fd;
     PIF handler;
     caddr_t data;
{
    PendingEntry *pe = (PendingEntry *) xmalloc(sizeof(PendingEntry));
    int old_size, i, j;

    debug(5, "storeRegister: FD %d <URL:%s>\n", fd, e->url);

    memset(pe, '\0', sizeof(PendingEntry));
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
    for (i = 0; i < (int) e->mem_obj->pending_list_size; i++)
	if (e->mem_obj->pending[i] == NULL)
	    break;

    if (i == e->mem_obj->pending_list_size) {
	/* grow the array */
	struct pentry **tmp = NULL;

	old_size = e->mem_obj->pending_list_size;

	/* set list_size to an appropriate amount */
	e->mem_obj->pending_list_size += MIN_PENDING;

	/* allocate, and copy old pending list over to the new one */
	tmp = (struct pentry **) xcalloc(e->mem_obj->pending_list_size,
	    sizeof(struct pentry *));
	for (j = 0; j < old_size; j++)
	    tmp[j] = e->mem_obj->pending[j];

	/* free the old list and set the new one */
	safe_free(e->mem_obj->pending);
	e->mem_obj->pending = tmp;

	debug(10, "storeRegister: grew pending list to %d for slot %d.\n",
	    e->mem_obj->pending_list_size, i);

    }
    e->mem_obj->pending[i] = pe;
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

    debug(10, "storeUnregister: called for FD %d <URL:%s>\n", fd, e->url);

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

    debug(10, "storeUnregister: returning %d\n", freed);
    return freed;
}

/* Call to delete behind upto "target lowest offset"
 * also, it update e_lowest_offset.
 */
void storeDeleteBehind(e)
     StoreEntry *e;
{
    int free_up_to;
    int target_offset;
    int n_client = 0;
    int i;

    debug(3, "storeDeleteBehind: Object: %s\n", e->key);
    debug(3, "storeDeleteBehind:\tOriginal Lowest Offset: %d \n", e->mem_obj->e_lowest_offset);

    free_up_to = e->mem_obj->e_lowest_offset;
    target_offset = 0;

    for (i = 0; i < e->mem_obj->client_list_size; ++i) {
	if (e->mem_obj->client_list[i] == NULL)
	    continue;
	if (((e->mem_obj->client_list[i]->last_offset < target_offset) ||
		(target_offset == 0))) {
	    n_client++;
	    target_offset = e->mem_obj->client_list[i]->last_offset;
	}
    }

    if (n_client == 0) {
	debug(3, "storeDeleteBehind:\tThere is no client in the list.\n");
	debug(3, "\t\tTry to delete as fast as possible.\n");
	target_offset = e->mem_obj->e_current_len;
    }
    debug(3, "storeDeleteBehind:\tThe target offset is : %d\n", target_offset);
    if (target_offset) {
	free_up_to = (int) e->mem_obj->data->mem_free_data_upto(e->mem_obj->data,
	    target_offset);
	debug(3, "                   Object is freed upto : %d\n", free_up_to);
	store_mem_size -= free_up_to - e->mem_obj->e_lowest_offset;
    }
    debug(3, "storeDeleteBehind:\tOutgoing Lowest Offset : %d\n", free_up_to);
    e->mem_obj->e_lowest_offset = free_up_to;
}

/* Call handlers waiting for  data to be appended to E. */
static void InvokeHandlers(e)
     StoreEntry *e;
{
    int i;

    /* walk the entire list looking for valid handlers */
    for (i = 0; i < (int) e->mem_obj->pending_list_size; i++) {
	if (e->mem_obj->pending[i] && e->mem_obj->pending[i]->handler) {
	    /* 
	     *  Once we call the handler, it is no longer needed 
	     *  until the write process sends all available data 
	     *  from the object entry. 
	     */
	    (e->mem_obj->pending[i]->handler)
		(e->mem_obj->pending[i]->fd, e, e->mem_obj->pending[i]->data);
	    safe_free(e->mem_obj->pending[i]);
	    e->mem_obj->pending[i] = NULL;
	}
    }

}

/* switch object to deleting behind mode 
 * call by retrieval module when object gets too big.
 */
void storeStartDeleteBehind(e)
     StoreEntry *e;
{
    debug(2, "storeStartDeleteBehind: Object: %s\n", e->key);
    if (e->flag & DELETE_BEHIND) {
	debug(2, "storeStartDeleteBehind:\tis already in delete behind mode.\n");
	return;
    }
    debug(2, "storeStartDeleteBehind:\tis now in delete behind mode.\n");
    /* change its key, so it couldn't be found by other client */
    storeChangeKey(e);
    BIT_SET(e->flag, DELETE_BEHIND);
    BIT_SET(e->flag, RELEASE_REQUEST);
    BIT_RESET(e->flag, CACHABLE);
    e->expires = cached_curtime;
}

/* Append incoming data from a primary server to an entry. */
int storeAppend(e, data, len)
     StoreEntry *e;
     char *data;
     int len;
{
    /* validity check -- sometimes it's called with bogus values */
    if (e == NULL || !has_mem_obj(e) || e->mem_obj->data == NULL) {
	debug(0, "storeAppend (len = %d): Invalid StoreEntry, aborting...\n",
	    len);
	if (len < 512)
	    fwrite(data, len, 1, debug_log);
	debug(0, "%s", storeToString(e));
	fatal_dump(NULL);
    }
    if (len) {
	debug(5, "storeAppend: appending %d bytes for %s\n", len, e->url);

	/* get some extra storage if needed */
	(void) storeGetMemSpace(len, 0);
	store_mem_size += len;
	debug(8, "storeAppend: growing store_mem_size by %d\n", len);
	debug(8, "storeAppend: store_mem_size = %d\n", store_mem_size);

	(void) e->mem_obj->data->mem_append(e->mem_obj->data,
	    data, len);
	e->mem_obj->e_current_len += len;
	debug(8, "storeAppend: e_current_len = %d\n",
	    e->mem_obj->e_current_len);
    }
    if ((e->status != STORE_ABORTED) && !(e->flag & DELAY_SENDING))
	InvokeHandlers(e);

    return 0;
}

/* add directory to swap disk */
int storeAddSwapDisk(path)
     char *path;
{
    if (cache_dirs == NULL)
	cache_dirs = create_dynamic_array(5, 5);
    insert_dynamic_array(cache_dirs, path);
    return ++ncache_dirs;
}

/* return the nth swap directory */
char *swappath(n)
     int n;
{
    return cache_dirs->collection[n % ncache_dirs];
}


/* return full name to swapfile */
char *storeSwapFullPath(fn, fullpath)
     int fn;
     char *fullpath;
{
    static char fullfilename[MAX_FILE_NAME_LEN];

    if (fullpath) {
	sprintf(fullpath, "%s/%02d/%d",
	    swappath(fn),
	    (fn / ncache_dirs) % SWAP_DIRECTORIES,
	    fn);
	return fullpath;
    }
    fullfilename[0] = '\0';
    sprintf(fullfilename, "%s/%02d/%d",
	swappath(fn),
	(fn / ncache_dirs) % SWAP_DIRECTORIES,
	fn);
    return fullfilename;
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
    debug(2, "storeSwapInHandle: <URL:%s>\n", e->url);

    if ((flag < 0) && (flag != DISK_EOF)) {
	debug(0, "storeSwapInHandle: SwapIn failure (err code = %d).\n", flag);
	put_free_8k_page(e->mem_obj->e_swap_buf);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	file_close(e->mem_obj->swap_fd);
	swapInError(-1, e);	/* Invokes storeAbort() and completes the I/O */
	return -1;
    }
    debug(5, "storeSwapInHandle: e->swap_offset   = %d\n",
	e->mem_obj->swap_offset);
    debug(5, "storeSwapInHandle: len              = %d\n",
	len);
    debug(5, "storeSwapInHandle: e->e_current_len = %d\n",
	e->mem_obj->e_current_len);
    debug(5, "storeSwapInHandle: e->object_len    = %d\n",
	e->object_len);

    /* always call these, even if len == 0 */
    e->mem_obj->swap_offset += len;
    storeAppend(e, buf, len);

    if (e->mem_obj->e_current_len < e->object_len && flag != DISK_EOF) {
	/* some more data to swap in, reschedule */
	file_read(e->mem_obj->swap_fd,
	    e->mem_obj->e_swap_buf,
	    SWAP_BUF,
	    e->mem_obj->swap_offset,
	    (FILE_READ_HD) storeSwapInHandle,
	    (caddr_t) e);
    } else {
	/* complete swapping in */
	storeSetMemStatus(e, IN_MEMORY);
	put_free_8k_page(e->mem_obj->e_swap_buf);
	file_close(e->mem_obj->swap_fd);
	debug(5, "storeSwapInHandle: SwapIn complete: <URL:%s> from %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	if (e->mem_obj->e_current_len != e->object_len) {
	    debug(0, "storeSwapInHandle: WARNING! Object size mismatch.\n");
	    debug(0, "  --> <URL:%s>\n", e->url);
	    debug(0, "  --> Expecting %d bytes from file: %s\n", e->object_len,
		storeSwapFullPath(e->swap_file_number, NULL));
	    debug(0, "  --> Only read %d bytes\n",
		e->mem_obj->e_current_len);
	}
	if (e->flag & RELEASE_REQUEST)
	    storeRelease(e);
    }
    return 0;
}

/* start swapping in */
int storeSwapInStart(e)
     StoreEntry *e;
{
    int fd;

    /* sanity check! */
    if ((e->swap_status != SWAP_OK) || (e->swap_file_number < 0)) {
	debug(0, "storeSwapInStart: <No filename:%d> ? <URL:%s>\n", e->swap_file_number, e->url);
	if (has_mem_obj(e))
	    e->mem_obj->swap_fd = -1;
	return -1;
    }
    /* create additional structure for object in memory */
    create_store_mem_obj(e);

    e->mem_obj->swap_fd = fd =
	file_open(storeSwapFullPath(e->swap_file_number, NULL), NULL, O_RDONLY);
    if (fd < 0) {
	debug(0, "storeSwapInStart: Unable to open swapfile: %s for\n\t<URL:%s>\n",
	    storeSwapFullPath(e->swap_file_number, NULL), e->url);
	storeSetMemStatus(e, NOT_IN_MEMORY);
	/* Invoke a store abort that should free the destroy_store_mem_obj(e); */
	return -1;
    }
    debug(5, "storeSwapInStart: initialized swap file '%s' for <URL:%s>\n",
	storeSwapFullPath(e->swap_file_number, NULL), e->url);

    e->mem_obj->data = memInit();
    ++meta_data.hot_vm;

    storeSetMemStatus(e, SWAPPING_IN);
    e->mem_obj->swap_offset = 0;

    e->mem_obj->e_swap_buf = get_free_8k_page();

    /* start swapping daemon */
    file_read(e->mem_obj->swap_fd,
	e->mem_obj->e_swap_buf,
	SWAP_BUF,
	e->mem_obj->swap_offset,
	(FILE_READ_HD) storeSwapInHandle,
	(caddr_t) e);
    return 0;
}

void storeSwapOutHandle(fd, flag, e)
     int fd;
     int flag;
     StoreEntry *e;
{
    static char filename[MAX_FILE_NAME_LEN];
    static char logmsg[6000];
    char *page_ptr = NULL;

    debug(5, "storeSwapOutHandle: <URL:%s>\n", e->url);

    e->timestamp = cached_curtime;
    storeSwapFullPath(e->swap_file_number, filename);
    page_ptr = e->mem_obj->e_swap_buf;

    if (flag < 0) {
	debug(1, "storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = NO_SWAP;
	put_free_8k_page(page_ptr);
	file_close(fd);
	BIT_SET(e->flag, RELEASE_REQUEST);
	if (e->swap_file_number != -1) {
	    file_map_bit_reset(e->swap_file_number);
	    safeunlink(filename, 0);	/* remove it */
	    e->swap_file_number = -1;
	}
	if (flag == DISK_NO_SPACE_LEFT) {
	    /* reduce the swap_size limit to the current size. */
	    setCacheSwapMax(store_swap_size);
	    store_swap_high = (long) (((float) getCacheSwapMax() *
		    (float) getCacheSwapHighWaterMark()) / (float) 100);
	    store_swap_low = (long) (((float) getCacheSwapMax() *
		    (float) getCacheSwapLowWaterMark()) / (float) 100);
	}
	return;
    }
    debug(6, "storeSwapOutHandle: e->swap_offset    = %d\n",
	e->mem_obj->swap_offset);
    debug(6, "storeSwapOutHandle: e->e_swap_buf_len = %d\n",
	e->mem_obj->e_swap_buf_len);
    debug(6, "storeSwapOutHandle: e->object_len     = %d\n",
	e->object_len);
    debug(6, "storeSwapOutHandle: store_swap_size   = %dk\n",
	store_swap_size);

    e->mem_obj->swap_offset += e->mem_obj->e_swap_buf_len;
    /* round up */
    store_swap_size += ((e->mem_obj->e_swap_buf_len + 1023) >> 10);
    if (e->mem_obj->swap_offset >= e->object_len) {
	/* swapping complete */
	e->swap_status = SWAP_OK;
	file_close(e->mem_obj->swap_fd);
	debug(5, "storeSwapOutHandle: SwapOut complete: <URL:%s> to %s.\n",
	    e->url, storeSwapFullPath(e->swap_file_number, NULL));
	put_free_8k_page(page_ptr);
	sprintf(logmsg, "FILE: %s URL: %s %d %d %d\n",
	    filename,
	    e->url,
	    (int) e->expires,
	    (int) e->timestamp,
	    e->object_len);
	/* Automatically freed by file_write because no-handlers */
	file_write(swaplog_fd,
	    xstrdup(logmsg),
	    strlen(logmsg),
	    swaplog_lock,
	    NULL,
	    NULL);
	/* check if it's request to be released. */
	if (e->flag & RELEASE_REQUEST)
	    storeRelease(e);
	return;
    }
    /* write some more data, reschedule itself. */
    storeCopy(e, e->mem_obj->swap_offset, SWAP_BUF,
	e->mem_obj->e_swap_buf, &(e->mem_obj->e_swap_buf_len));
    file_write(e->mem_obj->swap_fd, e->mem_obj->e_swap_buf,
	e->mem_obj->e_swap_buf_len, e->mem_obj->e_swap_access,
	storeSwapOutHandle, e);
    return;

}


/* start swapping object to disk */
int storeSwapOutStart(e)
     StoreEntry *e;
{
    int fd;
    static char swapfilename[MAX_FILE_NAME_LEN];

    /* Suggest a new swap file number */
    swapfileno = (swapfileno + 1) % (MAX_SWAP_FILE);
    /* Record the number returned */
    swapfileno = file_map_allocate(swapfileno);
    storeSwapFullPath(swapfileno, swapfilename);

    fd = file_open(swapfilename, NULL, O_RDWR | O_CREAT | O_TRUNC);
    if (fd < 0) {
	debug(0, "storeSwapOutStart: Unable to open swapfile: %s\n",
	    swapfilename);
	file_map_bit_reset(swapfileno);
	e->swap_file_number = -1;
	return -1;
    }
    e->mem_obj->swap_fd = fd;
    debug(5, "storeSwapOutStart: Begin SwapOut <URL:%s> to FD %d FILE %s.\n",
	e->url, fd, swapfilename);

    e->swap_file_number = swapfileno;
    if ((e->mem_obj->e_swap_access = file_write_lock(e->mem_obj->swap_fd)) < 0) {
	debug(0, "storeSwapOutStart: Unable to lock swapfile: %s\n",
	    swapfilename);
	file_map_bit_reset(e->swap_file_number);
	e->swap_file_number = -1;
	return -1;
    }
    e->swap_status = SWAPPING_OUT;
    e->mem_obj->swap_offset = 0;
    e->mem_obj->e_swap_buf = get_free_8k_page();
    e->mem_obj->e_swap_buf_len = 0;

    storeCopy(e, 0, SWAP_BUF, e->mem_obj->e_swap_buf,
	&(e->mem_obj->e_swap_buf_len));

    /* start swapping daemon */
    if (file_write(e->mem_obj->swap_fd,
	    e->mem_obj->e_swap_buf,
	    e->mem_obj->e_swap_buf_len,
	    e->mem_obj->e_swap_access,
	    storeSwapOutHandle,
	    e) != DISK_OK) {
	/* This shouldn't happen */
	fatal_dump(NULL);
    }
    return 0;
}

/* recreate meta data from disk image in swap directory */
void storeRebuildFromDisk()
{
    int objcount = 0;		/* # objects successfully reloaded */
    int expcount = 0;		/* # objects expired */
    int linecount = 0;		/* # lines parsed from cache logfile */
    int clashcount = 0;		/* # swapfile clashes avoided */
    int dupcount = 0;		/* # duplicates purged */
    static char line_in[4096];
    static char log_swapfile[1024];
    static char swapfile[1024];
    static char url[MAX_URL];
    char *t = NULL;
    StoreEntry *e = NULL;
    struct stat sb;
    time_t start, stop, r;
    time_t expires;
    time_t timestamp;
    time_t last_clean;
    int scan1, scan2, scan3;
    int delta;
    int i;
    int sfileno = 0;
    off_t size;
    int fast_mode = 0;

    for (i = 0; i < ncache_dirs; ++i)
	debug(1, "Rebuilding storage from disk image in %s\n", swappath(i));
    start = cached_curtime = time(NULL);

    sprintf(line_in, "%s/log-last-clean", swappath(0));
    if (stat(line_in, &sb) >= 0) {
	last_clean = sb.st_mtime;
	sprintf(line_in, "%s/log", swappath(0));
	if (stat(line_in, &sb) >= 0) {
	    fast_mode = (sb.st_mtime <= last_clean) ? 1 : 0;
	}
    }
    if (fast_mode)
	debug(1, "Rebuilding in FAST MODE.\n");

    /* go to top of the file */
    (void) lseek(swaplog_fd, 0L, SEEK_SET);

    memset(line_in, '\0', 4096);
    while (fgets(line_in, 4096, swaplog_stream)) {

	if ((linecount++ & 0x7F) == 0)	/* update current time */
	    cached_curtime = time(NULL);

	if ((linecount & 0xFFF) == 0)
	    debug(1, "  %7d Lines read so far.\n", linecount);

	debug(10, "line_in: %s", line_in);
	if ((line_in[0] == '\0') || (line_in[0] == '\n') ||
	    (line_in[0] == '#'))
	    continue;		/* skip bad lines */

	url[0] = log_swapfile[0] = '\0';
	expires = cached_curtime;

	scan3 = 0;
	size = 0;
	if (sscanf(line_in, "FILE: %[^ ] URL: %[^ ] %d %d %d",
		log_swapfile, url, &scan1, &scan2, &scan3) < 4) {
#ifdef UNLINK_ON_RELOAD
	    if (log_swapfile[0])
		safeunlink(log_swapfile, 0);
#endif
	    continue;
	}
	expires = (time_t) scan1;
	timestamp = (time_t) scan2;
	size = (off_t) scan3;
	if ((t = strrchr(log_swapfile, '/')))
	    sfileno = atoi(t + 1);
	else
	    sfileno = atoi(log_swapfile);
	storeSwapFullPath(sfileno, swapfile);

	/*
	 * Note that swapfile may be different than log_swapfile if
	 * another cache_dir is added.
	 */

	if (!scan3 || !fast_mode) {

	    if (stat(swapfile, &sb) < 0) {
		if (expires < cached_curtime) {
		    debug(3, "storeRebuildFromDisk: Expired: <URL:%s>\n", url);
#ifdef UNLINK_ON_RELOAD
		    safeunlink(swapfile, 1);
#endif
		    expcount++;
		} else {
		    debug(3, "storeRebuildFromDisk: Swap file missing: <URL:%s>: %s: %s.\n", url, swapfile, xstrerror());
#ifdef UNLINK_ON_RELOAD
		    safeunlink(log_swapfile, 1);
#endif
		}
		continue;
	    }
	    if ((size = sb.st_size) == 0) {
#ifdef UNLINK_ON_RELOAD
		safeunlink(log_swapfile, 1);
#endif
		continue;
	    }
	    /* timestamp might be a little bigger than sb.st_mtime */
	    delta = abs((int) (timestamp - sb.st_mtime));
	    if (delta > REBUILD_TIMESTAMP_DELTA_MAX) {
		/* this log entry doesn't correspond to this file */
		clashcount++;
		continue;
	    }
	    timestamp = sb.st_mtime;
	    debug(10, "storeRebuildFromDisk: Cached file exists: <URL:%s>: %s\n",
		url, swapfile);
	}
	if ((e = storeGet(url))) {
	    debug(6, "storeRebuildFromDisk: Duplicate: <URL:%s>\n", url);
	    storeRelease(e);
	    objcount--;
	    dupcount++;
	}
	if (expires < cached_curtime) {
	    debug(3, "storeRebuildFromDisk: Expired: <URL:%s>\n", url);
#ifdef UNLINK_ON_RELOAD
	    safeunlink(swapfile, 1);
#endif
	    expcount++;
	    continue;
	}
	/* update store_swap_size */
	store_swap_size += (int) ((size + 1023) >> 10);
	objcount++;

	fprintf(swaplog_tmp_stream, "FILE: %s URL: %s %d %d %d\n",
	    swapfile, url, (int) expires, (int) timestamp, (int) size);
	storeAddDiskRestore(url, sfileno, (int) size, expires, timestamp);
	CacheInfo->proto_newobject(CacheInfo,
	    CacheInfo->proto_id(url),
	    (int) size, TRUE);
    }

    fflush(swaplog_tmp_stream);
    stop = cached_curtime = time(NULL);
    r = stop - start;
    /* swapfileno = sfileno; */
    /* PBD: Start swapfileno at zero, so that old swap files are overwritten */
    debug(1, "Finished rebuilding storage from disk image.\n");
    debug(1, "  %7d Lines read from previous logfile.\n", linecount);
    debug(1, "  %7d Objects loaded.\n", objcount);
    debug(1, "  %7d Objects expired.\n", expcount);
    debug(1, "  %7d Duplicate URLs purged.\n", dupcount);
    debug(1, "  %7d Swapfile clashes avoided.\n", clashcount);
    debug(1, "  Took %d seconds (%6.1lf objects/sec).\n",
	r > 0 ? r : 0, (double) objcount / (r > 0 ? r : 1));
    debug(1, "  store_swap_size = %dk\n", store_swap_size);

    /* touch a timestamp file */
    sprintf(line_in, "%s/log-last-clean", swappath(0));
    file_close(file_open(line_in, NULL, O_WRONLY | O_CREAT | O_TRUNC));
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


/* Complete transfer into the local cache.  */
void storeComplete(e)
     StoreEntry *e;
{
    debug(5, "storeComplete: <URL:%s>\n", e->url);

    e->object_len = e->mem_obj->e_current_len;
    InvokeHandlers(e);
    e->lastref = cached_curtime;
    e->status = STORE_OK;
    storeSetMemStatus(e, IN_MEMORY);
    e->swap_status = NO_SWAP;
    /* start writing it to disk, exclude cache_object */
    if ((strncmp("cache_obj", e->url, 9) != 0) &&
	(e->flag & CACHABLE) &&
	!(e->flag & RELEASE_REQUEST) &&
	(e->type_id == REQ_GET)) {
	storeSwapOutStart(e);
    }
    /* free up incoming MIME */
    safe_free(e->mem_obj->mime_hdr);
    CacheInfo->proto_newobject(CacheInfo, CacheInfo->proto_id(e->url),
	e->object_len, FALSE);
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
    static char mime_hdr[300];
    static char abort_msg[2000];

    debug(6, "storeAbort: <URL:%s>\n", e->url);
    e->expires = cached_curtime + getNegativeTTL();
    e->status = STORE_ABORTED;
    storeSetMemStatus(e, IN_MEMORY);
    /* No DISK swap for negative cached object */
    e->swap_status = NO_SWAP;
    e->lastref = cached_curtime;
    /* In case some parent responds late and 
     * tries to restart the fetch, say that it's been
     * dispatched already.
     */
    BIT_SET(e->flag, REQ_DISPATCHED);

    storeLockObject(e);

    /* Count bytes faulted through cache but not moved to disk */
    CacheInfo->proto_touchobject(CacheInfo, CacheInfo->proto_id(e->url),
	e->mem_obj->e_current_len);
    CacheInfo->proto_touchobject(CacheInfo, CacheInfo->proto_id("abort:"),
	e->mem_obj->e_current_len);

    mk_mime_hdr(mime_hdr,
	(time_t) getNegativeTTL(),
	6 + strlen(msg),
	cached_curtime,
	"text/html");
    if (msg) {
	/* This can run off the end here. Be careful */
	if ((int) (strlen(msg) + strlen(mime_hdr) + 50) < 2000) {
	    sprintf(abort_msg, "HTTP/1.0 400 Cache Detected Error\r\n%s\r\n\r\n%s", mime_hdr, msg);
	} else {
	    debug(0, "storeAbort: WARNING: Must increase msg length!");
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
    return ((StoreEntry *) storeFindFirst(table));
}


/* get the next entry in the storage for a given search pointer */
StoreEntry *storeGetNext()
{
    return ((StoreEntry *) storeFindNext(table));
}



/* walk through every single entry in the storage and invoke a given routine */
int storeWalkThrough(proc, data)
     int (*proc) _PARAMS((StoreEntry * e, caddr_t data));
     caddr_t data;
{
    StoreEntry *e = NULL;
    int count = 0;
    int n = 0;

    for (e = storeGetFirst(); e; e = storeGetNext()) {
	if ((++n & 0xFF) == 0)
	    cached_curtime = time(NULL);
	if ((n & 0xFFF) == 0)
	    debug(2, "storeWalkThrough: %7d objects so far.\n", n);
	count += proc(e, data);
    }
    return count;
}


/* compare an object timestamp and see if ttl is expired. Free it if so. */
/* return 1 if it expired, 0 if not */
int removeOldEntry(e, data)
     StoreEntry *e;
     caddr_t data;
{
    time_t curtime = *((time_t *) data);

    debug(5, "removeOldEntry: Checking: %s\n", e->url);
    debug(6, "removeOldEntry:   *       curtime: %8ld\n", curtime);
    debug(6, "removeOldEntry:   *  e->timestamp: %8ld\n", e->timestamp);
    debug(6, "removeOldEntry:   * time in cache: %8ld\n",
	curtime - e->timestamp);
    debug(6, "removeOldEntry:   *  time-to-live: %8ld\n",
	e->expires - cached_curtime);

    if ((cached_curtime > e->expires) && (e->status != STORE_PENDING)) {
	return (storeRelease(e) == 0 ? 1 : 0);
    }
    return 0;
}


/* free up all ttl-expired objects */
int storePurgeOld()
{
    int n;

    debug(3, "storePurgeOld: Begin purging TTL-expired objects\n");
    n = storeWalkThrough(removeOldEntry, (caddr_t) & cached_curtime);
    debug(3, "storePurgeOld: Done purging TTL-expired objects.\n");
    debug(3, "storePurgeOld: %d objects expired\n", n);
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

    debug(2, "storeGetMemSpace: Starting...\n");

    LRU_list = create_dynamic_array(meta_data.store_in_mem_objects, MEM_LRUSCAN_BLOCK);
    pending_entry_list = create_dynamic_array(meta_data.store_in_mem_objects, MEM_LRUSCAN_BLOCK);

    for (e = storeGetInMemFirst(); e; e = storeGetInMemNext()) {
	n_scanned++;

	n_inmem++;

	if (e->status == STORE_PENDING) {
	    if (!(e->flag & DELETE_BEHIND)) {
		/* it's not deleting behind, we can do something about it. */
		insert_dynamic_array(pending_entry_list, e);
	    }
	    continue;
	}
	if (cached_curtime > e->expires) {
	    debug(2, "storeGetMemSpace: Expired: %s\n", e->url);
	    n_expired++;
	    /* Delayed release */
	    storeRelease(e);
	    continue;
	}
	if ((e->swap_status == SWAP_OK) && (e->mem_status != SWAPPING_IN) &&
	    (e->lock_count == 0)) {
	    insert_dynamic_array(LRU_list, e);
	} else if (((e->status == STORE_ABORTED) ||
		    (e->swap_status == NO_SWAP)) &&
	    (e->lock_count == 0)) {
	    n_aborted++;
	    insert_dynamic_array(LRU_list, e);
	} else {
	    n_cantpurge++;
	    mem_cantpurge += e->mem_obj->e_current_len;
	    debug(5, "storeGetMemSpace: Can't purge %7d bytes: %s\n",
		e->mem_obj->e_current_len, e->url);
	    if (e->swap_status != SWAP_OK)
		debug(5, "storeGetMemSpace: --> e->swap_status != SWAP_OK\n");
	    if (e->lock_count)
		debug(5, "storeGetMemSpace: --> e->lock_count %d\n", e->lock_count);
	}
    }
    debug(2, "storeGetMemSpace: Current size:     %7d bytes\n", store_mem_size);
    debug(2, "storeGetMemSpace: High W Mark:      %7d bytes\n", store_mem_high);
    debug(2, "storeGetMemSpace: Low W Mark:       %7d bytes\n", store_mem_low);
    debug(2, "storeGetMemSpace: Entry count:      %7d items\n", meta_data.store_entries);
    debug(2, "storeGetMemSpace: Scanned:          %7d items\n", n_scanned);
    debug(2, "storeGetMemSpace: In memory:        %7d items\n", n_inmem);
    debug(2, "storeGetMemSpace: Hot vm count:     %7d items\n", meta_data.hot_vm);
    debug(2, "storeGetMemSpace: Expired:          %7d items\n", n_expired);
    debug(2, "storeGetMemSpace: Negative Cached:  %7d items\n", n_aborted);
    debug(2, "storeGetMemSpace: Can't purge:      %7d items\n", n_cantpurge);
    debug(2, "storeGetMemSpace: Can't purge size: %7d bytes\n", mem_cantpurge);
    debug(2, "storeGetMemSpace: Sorting LRU_list: %7d items\n", LRU_list->index);
    qsort((char *) LRU_list->collection, LRU_list->index, sizeof(e), (int (*)(const void *, const void *)) compareLastRef);

    /* Kick LRU out until we have enough memory space */

    if (check_vm_number) {
	/* look for vm slot */
	for (i = 0; (i < LRU_list->index) && (meta_data.hot_vm > store_hotobj_low); ++i) {
	    if ((LRU = (StoreEntry *) LRU_list->collection[i]))
		if ((LRU->status != STORE_PENDING) && (LRU->swap_status == NO_SWAP)) {
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
		if ((LRU->status != STORE_PENDING) && (LRU->swap_status == NO_SWAP)) {
		    n_released++;
		    storeRelease(LRU);
		} else {
		    n_purged++;
		    storePurgeMem(LRU);
		}
	}
    }

    destroy_dynamic_array(LRU_list);

    debug(2, "storeGetMemSpace: After freeing size: %7d bytes\n", store_mem_size);
    debug(2, "storeGetMemSpace: Purged:             %7d items\n", n_purged);
    debug(2, "storeGetMemSpace: Released:           %7d items\n", n_released);


    if (check_vm_number) {
	/* don't check for size */
	destroy_dynamic_array(pending_entry_list);
	debug(2, "storeGetMemSpace: Done.\n");
	return 0;
    }
    if ((store_mem_size + size) < store_mem_high) {
	/* we don't care for hot_vm count here, just the storage size. */
	over_highwater = over_max = 0;
	destroy_dynamic_array(pending_entry_list);
	debug(2, "storeGetMemSpace: Done.\n");
	return 0;
    }
    if ((store_mem_size + size) < getCacheMemMax()) {
	/* We're over high water mark here, but still under absolute max */
	if (!over_highwater) {
	    /* print only once when the condition occur until it clears. */
	    debug(1, "storeGetMemSpace: Allocating beyond the high water mark with total size of %d\n",
		store_mem_size + size);
	    over_highwater = 1;
	}
	/* we can delete more than one if we want to be more aggressive. */
	entry_to_delete_behind = 1;
    } else {
	/* We're over absolute max */
	if (!over_max) {
	    /* print only once when the condition occur until it clears. */
	    debug(1, "storeGetMemSpace: Allocating beyond the MAX Store with total size of %d\n",
		store_mem_size + size);
	    debug(1, "       Start Deleting Behind for every pending objects\n:");
	    debug(1, "       You should really adjust your cache_mem, high/low water mark,\n");
	    debug(1, "       max object size to suit your need.\n");
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
	debug(1, "storeGetMemSpace: Due to memory flucuation, put %d objects to DELETE_BEHIND MODE.\n",
	    n_deleted_behind);
    }
    destroy_dynamic_array(pending_entry_list);
    debug(2, "storeGetMemSpace: Done.\n");
    return 0;
}

int compareSize(e1, e2)
     StoreEntry **e1, **e2;
{
    if (!e1 || !e2) {
	debug(1, "compareSize: Called with at least one null argument, shouldn't happen.\n");
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
    debug(2, "storeGetSwapSpace: Starting...\n");

    /* Set flag if swap size over high-water-mark */
    if (store_swap_size + kb_size > store_swap_high)
	fReduceSwap = 1;

    debug(2, "storeGetSwapSpace: Need %d bytes...\n", size);

    LRU_list = create_dynamic_array(LRU_cur_size, LRU_cur_size);
    /* remove expired objects until recover enough space or no expired objects */
    for (i = 0; i < STORE_BUCKETS; ++i) {
	int expired_in_one_bucket = 0;

	link_ptr = hash_get_bucket(table, storeGetBucketNum());
	if (link_ptr == NULL)
	    continue;
	/* this while loop handles one bucket of hash table */
	expired_in_one_bucket = 0;
	while (link_ptr) {
	    scanned++;
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;

	    /* Identify objects that aren't locked, for replacement */
	    if ((e->status != STORE_PENDING) &&		/* We're still fetching the object */
		(e->swap_status == SWAP_OK) &&	/* Only release it if it is on disk */
		(e->lock_count == 0) &&		/* Be overly cautious */
		(e->mem_status != SWAPPING_IN)) {	/* Not if it's being faulted into memory */
		if (cached_curtime > e->expires) {
		    debug(2, "storeRemoveExpiredObj: Expired: <URL:%s>\n", e->url);
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
		debug(2, "storeGetSwapSpace: Can't purge %7d bytes: <URL:%s>\n",
		    e->object_len, e->url);
		if (e->lock_count) {
		    debug(2, "\t\te->lock_count %d\n", e->lock_count);
		}
		if (e->swap_status == SWAPPING_OUT) {
		    debug(2, "\t\te->swap_status == SWAPPING_OUT\n");
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
	    debug(2, "storeGetSwapSpace: Finished, %d objects expired.\n",
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

    /* end of candidate selection */
    debug(2, "storeGetSwapSpace: Current Size:   %7d kbytes\n", store_swap_size);
    debug(2, "storeGetSwapSpace: High W Mark:    %7d kbytes\n", store_swap_high);
    debug(2, "storeGetSwapSpace: Low W Mark:     %7d kbytes\n", store_swap_low);
    debug(2, "storeGetSwapSpace: Entry count:    %7d items\n", meta_data.store_entries);
    debug(2, "storeGetSwapSpace: Scanned:        %7d items\n", scanned);
    debug(2, "storeGetSwapSpace: Expired:        %7d items\n", expired);
    debug(2, "storeGetSwapSpace: Locked:         %7d items\n", locked);
    debug(2, "storeGetSwapSpace: Locked Space:   %7d bytes\n", locked_size);
    debug(2, "storeGetSwapSpace: Scan in array:  %7d bytes\n", scan_in_objs);
    debug(2, "storeGetSwapSpace: LRU candidate:  %7d items\n", LRU_list->index);

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
		debug(2, "storeGetSwapSpace: Help! Can't remove objects. <%s>\n",
		    LRU->url);
	    }
	}
    }
    debug(2, "storeGetSwapSpace: After Freeing Size:   %7d kbytes\n", store_swap_size);

    /* free the list */
    destroy_dynamic_array(LRU_list);

    if ((store_swap_size + kb_size > store_swap_high)) {
	if (++swap_help > SWAP_MAX_HELP) {
	    debug(0, "storeGetSwapSpace: Nothing to free with %d Kbytes in use.\n",
		store_swap_size);
	    debug(0, "--> Asking for %d bytes\n", size);
	    debug(0, "WARNING! Repeated failures to allocate swap space!\n");
	    debug(0, "WARNING! Please check your disk space.\n");
	    swap_help = 0;
	} else {
	    debug(2, "storeGetSwapSpace: Nothing to free with %d Kbytes in use.\n",
		store_swap_size);
	    debug(2, "--> Asking for %d bytes\n", size);
	}
    } else {
	swap_help = 0;
    }

    debug(2, "storeGetSwapSpace: Finished, %d objects removed.\n", removed);
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

    /* If, for any reason we can't discard this object because of an
     * outstanding request, mark it for pending release */
    if (storeEntryLocked(e)) {
	BIT_SET(e->flag, RELEASE_REQUEST);
	return -1;
    }
    debug(5, "storeRelease: Releasing: %s\n", e->url);

    if (table == (HashID) 0)
	return -1;

    if (e->key == NULL) {
	debug(0, "storeRelease: NULL key for %s\n", e->url);
	debug(0, "Dump of Entry 'e':\n %s\n", storeToString(e));
	fatal_dump(NULL);
    }
    if ((hptr = hash_lookup(table, e->key)) == NULL) {
	debug(0, "storeRelease: Not Found: %s\n", e->url);
	debug(0, "Dump of Entry 'e':\n %s\n", storeToString(e));
	fatal_dump(NULL);
    }
    result = (StoreEntry *) hptr;

    if (result != e) {
	debug(0, "storeRelease: Duplicated entry? <URL:%s>\n",
	    result->url ? result->url : "NULL");
	debug(0, "Dump of Entry 'e':\n%s", storeToString(e));
	debug(0, "Dump of Entry 'result':\n%s", storeToString(result));
	fatal_dump(NULL);
    }
    if (e->type_id == REQUEST_OP_GET) {
	/* check if coresponding HEAD object exists. */
	hash_link *head_table_entry = NULL;
	head_table_entry = hash_lookup(table, storeGenerateKey(e->url, REQUEST_OP_HEAD));
	if (head_table_entry) {
	    head_result = (StoreEntry *) head_table_entry;
	    if (head_result) {
		/* recursive call here to free up /head/ */
		storeRelease(head_result);
	    }
	}
    }
    debug(3, "storeRelease: Release object key: %s \n", e->key);

    if (e->swap_status == SWAP_OK && (e->swap_file_number > -1)) {
	(void) safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 0);
	file_map_bit_reset(e->swap_file_number);
	e->swap_file_number = -1;
	store_swap_size -= (e->object_len + 1023) >> 10;
    }
    /* Discard byte count */
    CacheInfo->proto_purgeobject(CacheInfo,
	CacheInfo->proto_id(e->url),
	e->object_len);
    storeHashDelete(hptr);
    storeFreeEntry(e);
    return 0;
}


/* store change key */
void storeChangeKey(e)
     StoreEntry *e;
{
    StoreEntry *result = NULL;
    static char key[MAX_URL + 32];

    if (!e)
	return;

    if (e->key == NULL) {
	debug(0, "storeChangeKey: NULL key for %s\n", e->url);
	return;
    }
    if (table != (HashID) 0) {
	hash_link *table_entry = hash_lookup(table, e->key);
	if (table_entry)
	    result = (StoreEntry *) table_entry;
	if (result == e) {
	    storeHashDelete(table_entry);

	    key[0] = '\0';
	    sprintf(key, "/x%d/%s", keychange_count++, e->key);
	    if (!(result->flag & KEY_URL))
		safe_free(result->key);
	    result->key = xstrdup(key);

	    storeHashInsert(e);
	    BIT_SET(result->flag, KEY_CHANGE);
	    BIT_RESET(result->flag, KEY_URL);
	} else {
	    debug(1, "storeChangeKey: Key is not unique for key: %s\n", e->key);
	}
    }
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
	debug(0, "This entry should be valid.\n");
	debug(0, "%s", storeToString(e));
	fatal_dump(NULL);
    }
    return ((e->lock_count) ||
	(e->status == STORE_PENDING) ||
	(e->swap_status == SWAPPING_OUT) ||
	(e->mem_status == SWAPPING_IN)
	);
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
	debug(1, "storeCopy: Client Request a chunk of data in area lower than the lowest_offset\n");
	debug(1, "           Current Lowest offset : %d\n", e->mem_obj->e_lowest_offset);
	debug(1, "           Requested offset      : %d\n", stateoffset);
	/* can't really do anything here. Client may hang until lifetime runout. */
	return 0;
    }
    *size = (available_to_write >= maxSize) ?
	maxSize : available_to_write;

    debug(6, "storeCopy: avail_to_write=%d, store_offset=%d\n",
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
	    e->mem_obj->client_list = (ClientStatusEntry **) xrealloc(e->mem_obj->client_list, e->mem_obj->client_list_size * sizeof(ClientStatusEntry *));
	}
    } else {
	e->mem_obj->client_list_size += MIN_CLIENT;
	e->mem_obj->client_list = (ClientStatusEntry **) xcalloc(e->mem_obj->client_list_size, sizeof(ClientStatusEntry *));
	i = 0;
    }

    e->mem_obj->client_list[i] = (ClientStatusEntry *) xcalloc(1, sizeof(ClientStatusEntry));
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
	debug(1, "storeClientCopy: Client Request a chunk of data in area lower than the lowest_offset\n");
	debug(1, "                              fd : %d\n", fd);
	debug(1, "           Current Lowest offset : %d\n", e->mem_obj->e_lowest_offset);
	debug(1, "           Requested offset      : %d\n", stateoffset);
	/* can't really do anything here. Client may hang until lifetime runout. */
	return 0;
    }
    *size = (available_to_write >= maxSize) ?
	maxSize : available_to_write;

    debug(6, "storeCopy: avail_to_write=%d, store_offset=%d\n",
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




/*
 * Go through the first 300 bytes of MIME header of a cached object, returning
 * fields that match.
 */
char *storeMatchMime(e, mimehdr, buf, buf_len)
     StoreEntry *e;
     char *mimehdr;
     char *buf;
     int buf_len;
{
    int i;
    int offset = 0;

    offset = storeGrep(e, mimehdr, 300);

    buf[0] = '\0';

    if (offset) {
	storeCopy(e, offset, buf_len, buf, &buf_len);
	for (i = 0; i < buf_len; ++i) {
	    if (buf[i] == '\r') {
		buf[i] = ' ';
	    }			/* strip \r */
	    if (buf[i] == '\n') {
		buf[i] = '\0';
		break;
	    }
	}
	buf[buf_len - 1] = '\0';	/* always terminate at the end */
    }
    return (buf);
}

int storeGrep(e, string, nbytes)
     StoreEntry *e;
     char *string;
     int nbytes;
{
    if (e && has_mem_obj(e) && e->mem_obj->data && (nbytes > 0))
	return e->mem_obj->data->mem_grep(e->mem_obj->data, string, nbytes);

    return 0;
}


int storeEntryValidToSend(e)
     StoreEntry *e;
{
    if ((cached_curtime < e->expires) || (e->status == STORE_PENDING))
	return 1;
    return 0;
}

int storeInit()
{
    static char tmpbuf[FATAL_BUF_SIZE];
    static char swaplog_file[MAX_FILE_NAME_LEN];
    static char swaplog_tmp_file[MAX_FILE_NAME_LEN];
    int directory_created = 0;
    struct stat sb;
    int inx;
    char *path = NULL;

    (void) file_map_create(MAX_SWAP_FILE);

    for (inx = 0; inx < ncache_dirs; ++inx) {
	path = swappath(inx);
	debug(10, "storeInit: Creating swap space in %s\n", path);
	if (stat(path, &sb) < 0) {
	    /* we need to create a directory for swap file here. */
	    if (mkdir(path, 0777) < 0) {
		sprintf(tmpbuf,
		    "Failed to create swap directory %s: %s\n",
		    path, xstrerror());
		if (errno != EEXIST)
		    fatal(tmpbuf);
	    }
	    if (stat(path, &sb) < 0) {
		sprintf(tmpbuf,
		    "Failed to verify swap directory %s: %s\n",
		    path, xstrerror());
		fatal(tmpbuf);
	    }
	    debug(1, "storeInit: Created swap directory %s\n", path);
	    directory_created = 1;
	}
	if (zap_disk_store) {
	    debug(1, "storeInit: Zapping all objects on disk storage.\n");
	    /* This could be dangerous, second copy of cache can destroy the existing
	     * swap files of the previous cache. We may use rc file do it. */
	    tmpbuf[0] = '\0';
	    sprintf(tmpbuf, "cd %s; rm -rf log [0-9][0-9]", path);
	    debug(1, "storeInit: Running '%s'\n", tmpbuf);
	    system(tmpbuf);
	}
    }
    sprintf(swaplog_file, "%s/log", swappath(0));

    swaplog_fd = file_open(swaplog_file, NULL, O_RDWR | O_CREAT);
    if (swaplog_fd < 0) {
	sprintf(tmpbuf, "Cannot open swap logfile: %s\n", swaplog_file);
	fatal(tmpbuf);
    }
    swaplog_stream = fdopen(swaplog_fd, "a+");
    if (!swaplog_stream) {
	sprintf(tmpbuf, "Cannot open a stream for swap logfile: %s\n", swaplog_file);
	fatal(tmpbuf);
    }
    swaplog_lock = file_write_lock(swaplog_fd);

    sprintf(swaplog_tmp_file, "%s/log_tmp", swappath(0));

    swaplog_tmp_fd = file_open(swaplog_tmp_file, NULL, O_RDWR | O_TRUNC | O_CREAT);
    if (swaplog_tmp_fd < 0) {
	sprintf(tmpbuf, "Cannot open swap tmp logfile: %s\n", swaplog_tmp_file);
	fatal(tmpbuf);
    }
    swaplog_tmp_stream = fdopen(swaplog_tmp_fd, "a+");
    if (!swaplog_tmp_stream) {
	sprintf(tmpbuf, "Cannot open a stream for swap tmp logfile: %s\n", swaplog_tmp_file);
	fatal(tmpbuf);
    }
    if (!zap_disk_store) {
	ok_write_clean_log = 0;
	storeRebuildFromDisk();

	/* rename tmp_log to log */
	file_write_unlock(swaplog_fd, swaplog_lock);
	file_close(swaplog_fd);
	safeunlink(swaplog_file, 0);
	link(swaplog_tmp_file, swaplog_file);

	swaplog_fd = file_open(swaplog_file, NULL, O_RDWR | O_CREAT);
	if (swaplog_fd < 0) {
	    sprintf(tmpbuf, "Cannot reopen swap logfile: %s\n", swaplog_file);
	    fatal(tmpbuf);
	}
	swaplog_stream = fdopen(swaplog_fd, "a+");
	if (!swaplog_stream) {
	    sprintf(tmpbuf, "Cannot reopen a stream for swap logfile: %s\n", swaplog_file);
	    fatal(tmpbuf);
	}
	swaplog_lock = file_write_lock(swaplog_fd);
	ok_write_clean_log = 1;
    }
    /* close tmp_log file here. Possibly remove if it is not linked to
     * the real one. */
    file_close(swaplog_tmp_fd);
    safeunlink(swaplog_tmp_file, 0);

    /* Create Small directories in swap */
    if (directory_created || zap_disk_store) {
	int i, j;
	char name[1024];
	for (j = 0; j < ncache_dirs; j++) {
	    for (i = 0; i < SWAP_DIRECTORIES; i++) {
		sprintf(name, "%s/%02d", swappath(j), i);
		if (mkdir(name, 0755) < 0) {
		    if (errno != EEXIST) {
			sprintf(tmpbuf,
			    "Failed to make swap directory %s: %s\n",
			    name, xstrerror());
			fatal(tmpbuf);
		    }
		}
	    }
	}
    }
    store_mem_high = (long) (getCacheMemMax() / 100) *
	getCacheMemHighWaterMark();
    store_mem_low = (long) (getCacheMemMax() / 100) *
	getCacheMemLowWaterMark();

    store_hotobj_high = (int) (getCacheHotVmFactor() *
	store_mem_high / (1 << 20));
    store_hotobj_low = (int) (getCacheHotVmFactor() *
	store_mem_low / (1 << 20));

    /* check for validity */
    if (store_hotobj_low > store_hotobj_high)
	store_hotobj_low = store_hotobj_high;

    store_swap_high = (long) (getCacheSwapMax() / 100) *
	getCacheSwapHighWaterMark();
    store_swap_low = (long) (getCacheSwapMax() / 100) *
	getCacheSwapLowWaterMark();

    return 0;
}

/* 
 *  storeSanityCheck - verify that all swap storage areas exist, and
 *  are writable; otherwise, force -z.
 */
void storeSanityCheck()
{
    static char name[4096];
    static char tmpbuf[4096];
    int i;

    if (ncache_dirs < 1)
	storeAddSwapDisk(DEFAULT_SWAP_DIR);

    for (i = 0; i < SWAP_DIRECTORIES; i++) {
	sprintf(name, "%s/%02d", swappath(i), i);
	errno = 0;
	if (access(name, W_OK)) {
	    /* A very annoying problem occurs when access() fails because
	     * the system file table is full.  To prevent cached from
	     * deleting your entire disk cache on a whim, insist that the
	     * errno indicates that the directory doesn't exist */
	    if (errno != ENOENT)
		continue;
	    sprintf(tmpbuf, "WARNING: Cannot write to %s for storage swap area.\nForcing a *full restart* (e.g., cached -z)...", name);
	    if (syslog_enable)
		syslog(LOG_ALERT, tmpbuf);
	    fprintf(stderr, "cached: %s\n", tmpbuf);
	    zap_disk_store = 1;
	    return;
	}
    }
}

int urlcmp(url1, url2)
     char *url1, *url2;
{
    if (!url1 || !url2)
	death();
    return (strcmp(url1, url2));
}

int parse_file_number(s)
     char *s;
{
    int len;


    for (len = strlen(s); (len >= 0); --len) {
	if (s[len] == '/') {
	    return (atoi(&s[len + 1]));
	}
    }
    debug(1, "parse_file_number: Could not determine the swap file number from %s.\n", s);
    return (0);
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
    static int loop_count = 0;
    static unsigned int bucket = 0;
    hash_link *link_ptr = NULL, *next = NULL;
    StoreEntry *e = NULL;
    int rm_obj = 0;

    if (table == (HashID) 0)
	return 0;

    /* Scan row of hash table each second and free storage if we're
     * over the high-water mark */
    storeGetSwapSpace(0);

    /* Purges expired objects, check one bucket on each calling */
    if (loop_count++ >= STORE_MAINTAIN_RATE) {
	loop_count = 0;
	if (bucket >= STORE_BUCKETS)
	    bucket = 0;
	link_ptr = hash_get_bucket(table, bucket++);
	while (link_ptr) {
	    next = link_ptr->next;
	    e = (StoreEntry *) link_ptr;
	    if ((cached_curtime > e->expires) &&
		(e->swap_status == SWAP_OK)) {
		debug(2, "storeMaintainSwapSpace: Expired: <TTL:%d> <URL:%s>\n",
		    e->expires - cached_curtime, e->url);
		/* just call release. don't have to check for lock status.
		 * storeRelease will take care of that and set a pending flag
		 * if it's still locked. */
		storeRelease(e);
		++rm_obj;
	    }
	    link_ptr = next;
	}
    }
    return rm_obj;
}

int safeunlink(s, quiet)
     char *s;
     int quiet;
{
    int err;

    if ((err = unlink(s)) < 0)
	if (!quiet)
	    debug(1, "safeunlink: Couldn't delete %s. %s\n", s, xstrerror());
    return (err);
}


/*
 *  storeWriteCleanLog
 * 
 *  Writes a "clean" swap log file from in-memory metadata.
 */
int storeWriteCleanLog()
{
    StoreEntry *e = NULL;
    static char swapfilename[MAX_FILE_NAME_LEN];
    static char clean_log[MAX_FILE_NAME_LEN];
    static char swaplog_file[MAX_FILE_NAME_LEN];
    static char tmpbuf[FATAL_BUF_SIZE];
    FILE *fp = NULL;
    int n = 0;
    time_t start, stop, r;

    if (!ok_write_clean_log) {
	debug(1, "storeWriteCleanLog: Not currently OK to rewrite swap log.\n");
	debug(1, "storeWriteCleanLog: Operation aborted.\n");
	return 0;
    }
    debug(1, "storeWriteCleanLog: Starting...\n");
    start = cached_curtime = time(NULL);
    sprintf(clean_log, "%s/log_clean", swappath(0));
    sprintf(swaplog_file, "%s/log", swappath(0));
    if ((fp = fopen(clean_log, "a+")) == NULL) {
	debug(0, "storeWriteCleanLog: %s: %s", clean_log, xstrerror());
	return 0;
    }
    for (e = storeGetFirst(); e; e = storeGetNext()) {
	debug(5, "storeWriteCleanLog: <URL:%s>\n", e->url);
	if (e->swap_file_number < 0)
	    continue;
	if (e->swap_status != SWAP_OK)
	    continue;
	if (e->object_len <= 0)
	    continue;
	storeSwapFullPath(e->swap_file_number, swapfilename);
	fprintf(fp, "FILE: %s URL: %s %d %d %d\n",
	    swapfilename, e->url, (int) e->expires, (int) e->timestamp,
	    e->object_len);
	if ((++n & 0xFFF) == 0) {
	    cached_curtime = time(NULL);
	    debug(1, "  %7d lines written so far.\n", n);
	}
    }
    fclose(fp);

    if (file_write_unlock(swaplog_fd, swaplog_lock) != DISK_OK) {
	debug(0, "storeWriteCleanLog: Failed to unlock swaplog!\n");
	debug(0, "storeWriteCleanLog: Current swap logfile not replaced.\n");
	return 0;
    }
    if (rename(clean_log, swaplog_file) < 0) {
	debug(0, "storeWriteCleanLog: rename failed: %s\n",
	    xstrerror());
	return 0;
    }
    file_close(swaplog_fd);
    swaplog_fd = file_open(swaplog_file, NULL, O_RDWR | O_CREAT);
    if (swaplog_fd < 0) {
	sprintf(tmpbuf, "Cannot open swap logfile: %s\n", swaplog_file);
	fatal(tmpbuf);
    }
    swaplog_stream = fdopen(swaplog_fd, "a+");
    if (!swaplog_stream) {
	sprintf(tmpbuf, "Cannot open a stream for swap logfile: %s\n",
	    swaplog_file);
	fatal(tmpbuf);
    }
    swaplog_lock = file_write_lock(swaplog_fd);

    stop = cached_curtime = time(NULL);
    r = stop - start;
    debug(1, "  Finished.  Wrote %d lines.\n", n);
    debug(1, "  Took %d seconds (%6.1lf lines/sec).\n",
	r > 0 ? r : 0, (double) n / (r > 0 ? r : 1));

    /* touch a timestamp file */
    sprintf(swaplog_file, "%s/log-last-clean", swappath(0));
    file_close(file_open(swaplog_file, NULL, O_WRONLY | O_CREAT | O_TRUNC));
    return n;
}

int swapInError(fd_unused, entry)
     int fd_unused;
     StoreEntry *entry;
{
    cached_error_entry(entry, ERR_DISK_IO, xstrerror());
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
