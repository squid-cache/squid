#include "squid.h"

static void storeClientCopy2(StoreEntry * e, store_client * sc);
static SIH storeClientCopyFileOpened;
static void storeClientCopyFileRead(store_client * sc);
static DRCB storeClientCopyHandleRead;

/* check if there is any client waiting for this object at all */
/* return 1 if there is at least one client */
int
storeClientWaiting(const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    for (sc = mem->clients; sc; sc = sc->next) {
	if (sc->callback_data != NULL)
	    return 1;
    }
    return 0;
}

store_client *
storeClientListSearch(const MemObject * mem, void *data)
{
    store_client *sc;
    for (sc = mem->clients; sc; sc = sc->next) {
	if (sc->callback_data == data)
	    break;
    }
    return sc;
}

/* add client with fd to client list */
void
storeClientListAdd(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client **T;
    store_client *sc;
    assert(mem);
    if (storeClientListSearch(mem, data) != NULL)
	return;
    mem->nclients++;
    sc = memAllocate(MEM_STORE_CLIENT, 1);
    cbdataAdd(sc, MEM_STORE_CLIENT);	/* sc is callback_data for file_read */
    sc->callback_data = data;
    sc->seen_offset = 0;
    sc->copy_offset = 0;
    sc->swapin_fd = -1;
    sc->disk_op_in_progress = 0;
    sc->mem = mem;
    if (e->store_status == STORE_PENDING && mem->swapout.fd == -1)
	sc->type = STORE_MEM_CLIENT;
    else
	sc->type = STORE_DISK_CLIENT;
    for (T = &mem->clients; *T; T = &(*T)->next);
    *T = sc;
}

/* copy bytes requested by the client */
void
storeClientCopy(StoreEntry * e,
    off_t seen_offset,
    off_t copy_offset,
    size_t size,
    char *buf,
    STCB * callback,
    void *data)
{
    store_client *sc;
    static int recurse_detect = 0;
    assert(e->store_status != STORE_ABORTED);
    assert(recurse_detect < 3);	/* could == 1 for IMS not modified's */
    debug(20, 3) ("storeClientCopy: %s, seen %d, want %d, size %d, cb %p, cbdata %p\n",
	storeKeyText(e->key),
	(int) seen_offset,
	(int) copy_offset,
	(int) size,
	callback,
	data);
    sc = storeClientListSearch(e->mem_obj, data);
    assert(sc != NULL);
    assert(sc->callback == NULL);
    sc->copy_offset = copy_offset;
    sc->seen_offset = seen_offset;
    sc->callback = callback;
    sc->copy_buf = buf;
    sc->copy_size = size;
    sc->copy_offset = copy_offset;
    storeClientCopy2(e, sc);
    recurse_detect--;
}

static void
storeClientCopy2(StoreEntry * e, store_client * sc)
{
    STCB *callback = sc->callback;
    MemObject *mem = e->mem_obj;
    size_t sz;
    static int loopdetect = 0;
    assert(++loopdetect < 10);
    debug(20, 3) ("storeClientCopy2: %s\n", storeKeyText(e->key));
    assert(callback != NULL);
    if (e->store_status == STORE_ABORTED) {
#if USE_ASYNC_IO
	if (sc->disk_op_in_progress == 1) {
	    if (sc->swapin_fd >= 0)
		aioCancel(sc->swapin_fd, NULL);
	    else
		aioCancel(-1, sc);
	}
#endif
	sc->disk_op_in_progress = 0;
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, 0);
    } else if (e->store_status == STORE_OK && sc->copy_offset == e->object_len) {
	/* There is no more to send! */
#if USE_ASYNC_IO
	if (sc->disk_op_in_progress == 1) {
	    if (sc->swapin_fd >= 0)
		aioCancel(sc->swapin_fd, NULL);
	    else
		aioCancel(-1, sc);
	}
#endif
	sc->disk_op_in_progress = 0;
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, 0);
    } else if (e->store_status == STORE_PENDING && sc->seen_offset == mem->inmem_hi) {
	/* client has already seen this, wait for more */
	debug(20, 3) ("storeClientCopy2: Waiting for more\n");
    } else if (sc->copy_offset >= mem->inmem_lo && mem->inmem_lo < mem->inmem_hi) {
	/* What the client wants is in memory */
	debug(20, 3) ("storeClientCopy2: Copying from memory\n");
	sz = stmemCopy(mem->data, sc->copy_offset, sc->copy_buf, sc->copy_size);
#if USE_ASYNC_IO
	if (sc->disk_op_in_progress == 1) {
	    if (sc->swapin_fd >= 0)
		aioCancel(sc->swapin_fd, NULL);
	    else
		aioCancel(-1, sc);
	}
#endif
	sc->disk_op_in_progress = 0;
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, sz);
    } else if (sc->swapin_fd < 0) {
	debug(20, 3) ("storeClientCopy2: Need to open swap in file\n");
	assert(sc->type == STORE_DISK_CLIENT);
	/* gotta open the swapin file */
	/* assert(sc->copy_offset == 0); */
	if (sc->disk_op_in_progress == 0) {
	    sc->disk_op_in_progress = 1;
	    storeSwapInStart(e, storeClientCopyFileOpened, sc);
	} else {
	    debug(20, 2) ("storeClientCopy2: Averted multiple fd operation\n");
	}
    } else {
	debug(20, 3) ("storeClientCopy: reading from disk FD %d\n",
	    sc->swapin_fd);
	assert(sc->type == STORE_DISK_CLIENT);
	if (sc->disk_op_in_progress == 0) {
	    sc->disk_op_in_progress = 1;
	    storeClientCopyFileRead(sc);
	} else {
	    debug(20, 2) ("storeClientCopy2: Averted multiple fd operation\n");
	}
    }
    --loopdetect;
}

static void
storeClientCopyFileOpened(int fd, void *data)
{
    store_client *sc = data;
    STCB *callback = sc->callback;
    if (fd < 0) {
	debug(20, 3) ("storeClientCopyFileOpened: failed\n");
	sc->disk_op_in_progress = 0;
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, -1);
	return;
    }
    sc->swapin_fd = fd;
    storeClientCopyFileRead(sc);
}

static void
storeClientCopyFileRead(store_client * sc)
{
    assert(sc->callback != NULL);
    file_read(sc->swapin_fd,
	sc->copy_buf,
	sc->copy_size,
	sc->copy_offset,
	storeClientCopyHandleRead,
	sc);
}

static void
storeClientCopyHandleRead(int fd, const char *buf, int len, int flagnotused, void *data)
{
    store_client *sc = data;
    MemObject *mem = sc->mem;
    STCB *callback = sc->callback;
    int hdr_len = 0;
    assert(sc->disk_op_in_progress != 0);
    sc->disk_op_in_progress = 0;
    assert(sc->callback != NULL);
    debug(20, 3) ("storeClientCopyHandleRead: FD %d, len %d\n", fd, len);
#if USE_SWAP_HEADERS
	/* XXX: BROKEN */
    if (sc->copy_offset == 0 && len > 0 && mem != NULL) {
	hdr_len = storeGetMetaBuf(buf, mem);
	memmove((char *) buf, (char *) (buf + hdr_len), len - hdr_len);
	len -= hdr_len;
	httpParseReplyHeaders(buf, mem->reply);
    }
#endif
    sc->callback = NULL;
    callback(sc->callback_data, sc->copy_buf, len);
}

int
storeClientCopyPending(StoreEntry * e, void *data)
{
    /* return 1 if there is a callback registered for this client */
    store_client *sc = storeClientListSearch(e->mem_obj, data);
    if (sc == NULL)
	return 0;
    if (sc->callback == NULL)
	return 0;
    return 1;
}

int
storeUnregister(StoreEntry * e, void *data)
{
    MemObject *mem = e->mem_obj;
    store_client *sc;
    store_client **S;
    STCB *callback;
    if (mem == NULL)
	return 0;
    debug(20, 3) ("storeUnregister: called for '%s'\n", storeKeyText(e->key));
    for (S = &mem->clients; (sc = *S) != NULL; S = &(*S)->next) {
	if (sc->callback_data == data)
	    break;
    }
    if (sc == NULL)
	return 0;
    *S = sc->next;
    mem->nclients--;
    sc->disk_op_in_progress = 0;
    if (e->store_status == STORE_OK && e->swap_status != SWAPOUT_DONE)
	storeCheckSwapOut(e);
    if (sc->swapin_fd > -1) {
	commSetSelect(sc->swapin_fd, COMM_SELECT_READ, NULL, NULL, 0);
	file_close(sc->swapin_fd);
    }
#if USE_ASYNC_IO
    else
	aioCancel(-1, sc);
#endif
    if ((callback = sc->callback) != NULL) {
	/* callback with ssize = -1 to indicate unexpected termination */
	debug(20, 3) ("storeUnregister: store_client for %s has a callback\n",
	    mem->url);
	sc->callback = NULL;
	callback(sc->callback_data, sc->copy_buf, -1);
    }
    cbdataFree(sc);
    return 1;
}

off_t
storeLowestMemReaderOffset(const StoreEntry * entry)
{
    const MemObject *mem = entry->mem_obj;
    off_t lowest = mem->inmem_hi;
    store_client *sc;
    store_client *nx = NULL;
    for (sc = mem->clients; sc; sc = nx) {
	nx = sc->next;
	if (sc->callback_data == NULL)	/* open slot */
	    continue;
	if (sc->type != STORE_MEM_CLIENT)
	    continue;
	if (sc->copy_offset < lowest)
	    lowest = sc->copy_offset;
    }
    return lowest;
}

/* Call handlers waiting for  data to be appended to E. */
void
InvokeHandlers(StoreEntry * e)
{
    int i = 0;
    MemObject *mem = e->mem_obj;
    store_client *sc;
    store_client *nx = NULL;
    assert(mem->clients != NULL || mem->nclients == 0);
    debug(20, 3) ("InvokeHandlers: %s\n", storeKeyText(e->key));
    /* walk the entire list looking for valid callbacks */
    for (sc = mem->clients; sc; sc = nx) {
	nx = sc->next;
	debug(20, 3) ("InvokeHandlers: checking client #%d\n", i++);
	if (sc->callback_data == NULL)
	    continue;
	if (sc->callback == NULL)
	    continue;
	storeClientCopy2(e, sc);
    }
}

int
storePendingNClients(const StoreEntry * e)
{
    int npend = 0;
    MemObject *mem = e->mem_obj;
    store_client *sc;
    store_client *nx = NULL;
    if (mem == NULL)
	return 0;
    for (sc = mem->clients; sc; sc = nx) {
	nx = sc->next;
	/* Changed from callback_data to just callback.  There can be no use */
	/* for callback_data without a callback, and sc->callback we know */
	/* gets reset, but not necessarily sc->callback_data */
	if (sc->callback == NULL)
	    continue;
	npend++;
    }
    return npend;
}
