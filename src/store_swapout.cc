#include "squid.h"

typedef struct swapout_ctrl_t {
    char *swapfilename;
    int oldswapstatus;
    StoreEntry *e;
} swapout_ctrl_t;

static void storeSwapoutFileOpened(void *data, int fd, int errcode);

/* start swapping object to disk */
void
storeSwapOutStart(StoreEntry * e)
{
    swapout_ctrl_t *ctrlp;
    LOCAL_ARRAY(char, swapfilename, SQUID_MAXPATHLEN);
    storeLockObject(e);
#if !MONOTONIC_STORE
    if ((e->swap_file_number = storeGetUnusedFileno()) < 0)
#endif
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
	ctrlp, e);
}

void
storeSwapOutHandle(int fdnotused, int flag, size_t len, void *data)
{
    StoreEntry *e = data;
    MemObject *mem = e->mem_obj;
    debug(20, 3) ("storeSwapOutHandle: '%s', len=%d\n", storeKeyText(e->key), (int) len);
    if (flag < 0) {
	debug(20, 1) ("storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = SWAPOUT_NONE;
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
	    e->swap_file_number = -1;
	}
	if (flag == DISK_NO_SPACE_LEFT) {
	    /* reduce the swap_size limit to the current size. */
	    Config.Swap.maxSize = store_swap_size;
	    storeConfigure();
	}
	storeReleaseRequest(e);
	storeSwapOutFileClose(e);
	return;
    }
#if USE_ASYNC_IO
    if (mem == NULL) {
	debug(20, 1) ("storeSwapOutHandle: mem == NULL : Cancelling swapout\n");
	return;
    }
#else
    assert(mem != NULL);
#endif
    mem->swapout.done_offset += len;
    if (e->store_status == STORE_PENDING || mem->swapout.done_offset < e->object_len + mem->swapout.meta_len) {
	storeCheckSwapOut(e);
	return;
    }
    /* swapping complete */
    debug(20, 5) ("storeSwapOutHandle: SwapOut complete: '%s' to %s.\n",
	mem->url, storeSwapFullPath(e->swap_file_number, NULL));
    e->swap_status = SWAPOUT_DONE;
    storeDirUpdateSwapSize(e->swap_file_number, e->object_len, 1);
    if (storeCheckCachable(e)) {
	storeLog(STORE_LOG_SWAPOUT, e);
#if 0
	storeDirSwapLog(e);
#endif
    }
    /* Note, we don't otherwise call storeReleaseRequest() here because
     * storeCheckCachable() does it for is if necessary */
    storeSwapOutFileClose(e);
}

void
storeCheckSwapOut(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    off_t lowest_offset;
    off_t new_mem_lo;
    size_t swapout_size;
    char *swap_buf;
    ssize_t swap_buf_len;
    int x;
    int hdr_len = 0;
    assert(mem != NULL);
    /* should we swap something out to disk? */
    debug(20, 3) ("storeCheckSwapOut: %s\n", mem->url);
    debug(20, 3) ("storeCheckSwapOut: store_status = %s\n",
	storeStatusStr[e->store_status]);
    if (e->store_status == STORE_ABORTED) {
	assert(EBIT_TEST(e->flag, RELEASE_REQUEST));
	storeSwapOutFileClose(e);
	return;
    }
    debug(20, 3) ("storeCheckSwapOut: mem->inmem_lo = %d\n",
	(int) mem->inmem_lo);
    debug(20, 3) ("storeCheckSwapOut: mem->inmem_hi = %d\n",
	(int) mem->inmem_hi);
    debug(20, 3) ("storeCheckSwapOut: swapout.queue_offset = %d\n",
	(int) mem->swapout.queue_offset);
    debug(20, 3) ("storeCheckSwapOut: swapout.done_offset = %d\n",
	(int) mem->swapout.done_offset);
#if USE_ASYNC_IO
    if (mem->inmem_hi < mem->swapout.queue_offset) {
	storeAbort(e, 0);
	assert(EBIT_TEST(e->flag, RELEASE_REQUEST));
	storeSwapOutFileClose(e);
	return;
    }
#else
    assert(mem->inmem_hi >= mem->swapout.queue_offset);
#endif
    swapout_size = (size_t) (mem->inmem_hi - mem->swapout.queue_offset);
    lowest_offset = storeLowestMemReaderOffset(e);
    debug(20, 3) ("storeCheckSwapOut: lowest_offset = %d\n",
	(int) lowest_offset);
    assert(lowest_offset >= mem->inmem_lo);

    new_mem_lo = lowest_offset;
    if (!EBIT_TEST(e->flag, ENTRY_CACHABLE)) {
	if (!EBIT_TEST(e->flag, KEY_PRIVATE))
	    debug(20, 0) ("storeCheckSwapOut: Attempt to swap out a non-cacheable non-private object!\n");
	stmemFreeDataUpto(mem->data, new_mem_lo);
	mem->inmem_lo = new_mem_lo;
	return;
    }
    if (mem->swapout.queue_offset < new_mem_lo)
	new_mem_lo = mem->swapout.queue_offset;
    stmemFreeDataUpto(mem->data, new_mem_lo);
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
	 * here again */
	return;
    }
    if (e->swap_status == SWAPOUT_OPENING)
	return;
    assert(mem->swapout.fd > -1);
    swap_buf = memAllocate(MEM_DISK_BUF, 1);
    if (mem->swapout.queue_offset == 0)
	hdr_len = storeBuildMetaData(e, swap_buf);

    if (swapout_size > STORE_SWAP_BUF - hdr_len)
	swapout_size = STORE_SWAP_BUF - hdr_len;

    swap_buf_len = stmemCopy(mem->data,
	mem->swapout.queue_offset,
	swap_buf + hdr_len,
	swapout_size) + hdr_len;

    if (swap_buf_len < 0) {
	debug(20, 1) ("stmemCopy returned %d for '%s'\n", swap_buf_len, storeKeyText(e->key));
	/* XXX This is probably wrong--we should storeRelease()? */
	storeDirMapBitReset(e->swap_file_number);
	safeunlink(storeSwapFullPath(e->swap_file_number, NULL), 1);
	e->swap_file_number = -1;
	e->swap_status = SWAPOUT_NONE;
	memFree(MEM_DISK_BUF, swap_buf);
	storeSwapOutFileClose(e);
	return;
    }
    debug(20, 3) ("storeCheckSwapOut: swap_buf_len = %d\n", (int) swap_buf_len);
    assert(swap_buf_len > 0);
    debug(20, 3) ("storeCheckSwapOut: swapping out %d bytes from %d\n",
	swap_buf_len, mem->swapout.queue_offset);
    mem->swapout.queue_offset += swap_buf_len - hdr_len;
    x = file_write(mem->swapout.fd,
	-1,
	swap_buf,
	swap_buf_len,
	storeSwapOutHandle,
	e,
	memFreeDISK);
    assert(x == DISK_OK);
}

void
storeSwapOutFileClose(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    if (mem->swapout.fd > -1)
	file_close(mem->swapout.fd);
#if USE_ASYNC_IO
    else
	aioCancel(-1, e);	/* Make doubly certain pending ops are gone */
#endif
    mem->swapout.fd = -1;
    storeUnlockObject(e);
}

static void
storeSwapoutFileOpened(void *data, int fd, int errcode)
{
    swapout_ctrl_t *ctrlp = data;
    int oldswapstatus = ctrlp->oldswapstatus;
    char *swapfilename = ctrlp->swapfilename;
    StoreEntry *e = ctrlp->e;
    MemObject *mem;
    xfree(ctrlp);
    if (fd == -2 && errcode == -2) {	/* Cancelled - Clean up */
	xfree(swapfilename);
	return;
    }
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
	mem->url, fd, swapfilename);
    xfree(swapfilename);
    debug(20, 5) ("swap_file_number=%08X\n", e->swap_file_number);
    storeCheckSwapOut(e);
}
