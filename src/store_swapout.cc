#include "squid.h"

typedef struct swapout_ctrl_t {
    char *swapfilename;
    int oldswapstatus;
    StoreEntry *e;
} swapout_ctrl_t;

static FOCB storeSwapOutFileOpened;
static off_t storeSwapOutObjectBytesOnDisk(const MemObject *);

/* start swapping object to disk */
void
storeSwapOutStart(StoreEntry * e)
{
    swapout_ctrl_t *ctrlp = xmalloc(sizeof(swapout_ctrl_t));
    assert(e->mem_obj);
    cbdataAdd(ctrlp, MEM_NONE);
    storeLockObject(e);
    e->swap_file_number = storeDirMapAllocate();
    ctrlp->swapfilename = xstrdup(storeSwapFullPath(e->swap_file_number, NULL));
    ctrlp->e = e;
    ctrlp->oldswapstatus = e->swap_status;
    e->swap_status = SWAPOUT_OPENING;
    e->mem_obj->swapout.ctrl = ctrlp;
    file_open(ctrlp->swapfilename,
	O_WRONLY | O_CREAT | O_TRUNC,
	storeSwapOutFileOpened,
	ctrlp,
	e);
}

void
storeSwapOutHandle(int fdnotused, int flag, size_t len, void *data)
{
    swapout_ctrl_t *ctrlp = data;
    StoreEntry *e = ctrlp->e;
    MemObject *mem = e->mem_obj;
    debug(20, 3) ("storeSwapOutHandle: '%s', len=%d\n", storeKeyText(e->key), (int) len);
    if (flag < 0) {
	debug(20, 1) ("storeSwapOutHandle: SwapOut failure (err code = %d).\n",
	    flag);
	e->swap_status = SWAPOUT_NONE;
	if (e->swap_file_number > -1) {
	    storeUnlinkFileno(e->swap_file_number);
	    storeDirMapBitReset(e->swap_file_number);
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
    assert(mem->swap_hdr_sz != 0);
    mem->swapout.done_offset += len;
    if (e->store_status == STORE_PENDING) {
	storeCheckSwapOut(e);
	return;
    } else if (mem->swapout.done_offset < objectLen(e) + mem->swap_hdr_sz) {
	storeCheckSwapOut(e);
	return;
    }
    /* swapping complete */
    debug(20, 5) ("storeSwapOutHandle: SwapOut complete: '%s' to %s.\n",
	storeUrl(e), storeSwapFullPath(e->swap_file_number, NULL));
    e->swap_file_sz = objectLen(e) + mem->swap_hdr_sz;
    e->swap_status = SWAPOUT_DONE;
    storeDirUpdateSwapSize(e->swap_file_number, e->swap_file_sz, 1);
    if (storeCheckCachable(e)) {
	storeLog(STORE_LOG_SWAPOUT, e);
	storeDirSwapLog(e, SWAP_LOG_ADD);
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
    off_t on_disk;
    size_t swapout_size;
    char *swap_buf;
    ssize_t swap_buf_len;
    int hdr_len = 0;
    assert(mem != NULL);
    /* should we swap something out to disk? */
    debug(20, 3) ("storeCheckSwapOut: %s\n", storeUrl(e));
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
	    debug(20, 3) ("storeCheckSwapOut: Attempt to swap out a non-cacheable non-private object!\n");
	stmemFreeDataUpto(&mem->data_hdr, new_mem_lo);
	mem->inmem_lo = new_mem_lo;
	return;
    }
#if USE_QUEUE_OFFSET
    /*
     * This feels wrong.  We should only free up to what we know
     * has been written to disk, not what has been queued for
     * writing.  Otherwise there will be a chunk of the data which
     * is not in memory and is not yet on disk.
     */
    if (mem->swapout.queue_offset < new_mem_lo)
	new_mem_lo = mem->swapout.queue_offset;
#else
    if ((on_disk = storeSwapOutObjectBytesOnDisk(mem)) < new_mem_lo)
	new_mem_lo = on_disk;
#endif
    stmemFreeDataUpto(&mem->data_hdr, new_mem_lo);
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
    if (swapout_size > STORE_SWAP_BUF)
	swapout_size = STORE_SWAP_BUF;
    swap_buf = memAllocate(MEM_DISK_BUF);
    swap_buf_len = stmemCopy(&mem->data_hdr,
	mem->swapout.queue_offset,
	swap_buf,
	swapout_size);
    if (swap_buf_len < 0) {
	debug(20, 1) ("stmemCopy returned %d for '%s'\n", swap_buf_len, storeKeyText(e->key));
	/* XXX This is probably wrong--we should storeRelease()? */
	storeUnlinkFileno(e->swap_file_number);
	storeDirMapBitReset(e->swap_file_number);
	e->swap_file_number = -1;
	e->swap_status = SWAPOUT_NONE;
	memFree(MEM_DISK_BUF, swap_buf);
	storeSwapOutFileClose(e);
	return;
    }
    debug(20, 3) ("storeCheckSwapOut: swap_buf_len = %d\n", (int) swap_buf_len);
    assert(swap_buf_len > 0);
    debug(20, 3) ("storeCheckSwapOut: swapping out %d bytes from %d\n",
	swap_buf_len, (int) mem->swapout.queue_offset);
    mem->swapout.queue_offset += swap_buf_len - hdr_len;
    file_write(mem->swapout.fd,
	-1,
	swap_buf,
	swap_buf_len,
	storeSwapOutHandle,
	mem->swapout.ctrl,
	memFreeDISK);
}

void
storeSwapOutFileClose(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    swapout_ctrl_t *ctrlp;
    assert(mem != NULL);
    debug(20, 3) ("storeSwapOutFileClose: %s\n", storeKeyText(e->key));
    if (mem->swapout.fd < 0) {
#if USE_ASYNC_IO
	aioCancel(-1, e);	/* Make doubly certain pending ops are gone */
#endif
	return;
    }
    ctrlp = mem->swapout.ctrl;
    file_close(mem->swapout.fd);
    mem->swapout.fd = -1;
    xfree(ctrlp->swapfilename);
    cbdataFree(ctrlp);
    mem->swapout.ctrl = NULL;
    storeUnlockObject(e);
}

static void
storeSwapOutFileOpened(void *data, int fd, int errcode)
{
    swapout_ctrl_t *ctrlp = data;
    StoreEntry *e = ctrlp->e;
    MemObject *mem = e->mem_obj;
    int swap_hdr_sz = 0;
    tlv *tlv_list;
    char *buf;
    if (fd == -2 && errcode == -2) {	/* Cancelled - Clean up */
	xfree(ctrlp->swapfilename);
	cbdataFree(ctrlp);
	mem->swapout.ctrl = NULL;
	return;
    }
    assert(e->swap_status == SWAPOUT_OPENING);
    if (fd < 0) {
	debug(20, 0) ("storeSwapOutFileOpened: Unable to open swapfile: %s\n",
	    ctrlp->swapfilename);
	storeDirMapBitReset(e->swap_file_number);
	e->swap_file_number = -1;
	e->swap_status = ctrlp->oldswapstatus;
	xfree(ctrlp->swapfilename);
	cbdataFree(ctrlp);
	mem->swapout.ctrl = NULL;
	return;
    }
    mem->swapout.fd = (short) fd;
    e->swap_status = SWAPOUT_WRITING;
    debug(20, 5) ("storeSwapOutFileOpened: Begin SwapOut '%s' to FD %d '%s'\n",
	storeUrl(e), fd, ctrlp->swapfilename);
    debug(20, 5) ("swap_file_number=%08X\n", e->swap_file_number);
    tlv_list = storeSwapMetaBuild(e);
    buf = storeSwapMetaPack(tlv_list, &swap_hdr_sz);
    storeSwapTLVFree(tlv_list);
    mem->swap_hdr_sz = (size_t) swap_hdr_sz;
    file_write(mem->swapout.fd,
	-1,
	buf,
	mem->swap_hdr_sz,
	storeSwapOutHandle,
	ctrlp,
	xfree);
}

/*
 * Return 1 if we have some data queued.  If there is no data queued,
 * then 'done_offset' equals 'queued_offset' + 'swap_hdr_sz'
 *
 * done_offset represents data written to disk (including the swap meta
 * header), but queued_offset is relative to the in-memory data, and
 * does not include the meta header.
 */
int
storeSwapOutWriteQueued(MemObject * mem)
{
    /*
     * this function doesn't get called much, so I'm using
     * local variables to improve readability.  pphhbbht.
     */
    off_t queued = mem->swapout.queue_offset;
    off_t done = mem->swapout.done_offset;
    size_t hdr = mem->swap_hdr_sz;
    assert(queued + hdr >= done);
    return (queued + hdr > done);
}


/*
 * How much of the object data is on the disk?
 */
static off_t
storeSwapOutObjectBytesOnDisk(const MemObject * mem)
{
    /*
     * NOTE: done_offset represents the disk file size,
     * not the amount of object data on disk.
     * 
     * If we don't have at least 'swap_hdr_sz' bytes
     * then none of the object data is on disk.
     *
     * This should still be safe if swap_hdr_sz == 0,
     * meaning we haven't even opened the swapout file
     * yet.
     */
    if (mem->swapout.done_offset <= mem->swap_hdr_sz)
	return 0;
    return mem->swapout.done_offset - mem->swap_hdr_sz;
}
