
/*
 * $Id: store_swapout.cc,v 1.50 1999/05/22 02:31:20 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager Swapout Functions
 * AUTHOR: Duane Wessels
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

static off_t storeSwapOutObjectBytesOnDisk(const MemObject *);
static void storeSwapOutStart(StoreEntry * e);
static STIOCB storeSwapOutFileClosed;

/* start swapping object to disk */
static void
storeSwapOutStart(StoreEntry * e)
{
    generic_cbdata *c;
    MemObject *mem = e->mem_obj;
    int swap_hdr_sz = 0;
    tlv *tlv_list;
    char *buf;
    assert(mem);
    storeLockObject(e);
    e->swap_file_number = storeDirMapAllocate();
    c = xcalloc(1, sizeof(*c));
    c->data = e;
    cbdataAdd(c, cbdataXfree, 0);
    mem->swapout.sio = storeOpen(e->swap_file_number,
	O_WRONLY, storeSwapOutFileClosed, c);
    assert(mem->swapout.sio != NULL);
    cbdataLock(mem->swapout.sio);
    e->swap_status = SWAPOUT_WRITING;
    debug(20, 5) ("storeSwapOutStart: Begin SwapOut '%s' to fileno %08X\n",
	storeUrl(e), e->swap_file_number);
    tlv_list = storeSwapMetaBuild(e);
    buf = storeSwapMetaPack(tlv_list, &swap_hdr_sz);
    storeSwapTLVFree(tlv_list);
    mem->swap_hdr_sz = (size_t) swap_hdr_sz;
    storeWrite(mem->swapout.sio, buf, mem->swap_hdr_sz, 0, xfree);
}

void
storeSwapOut(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    off_t lowest_offset;
    off_t new_mem_lo;
    off_t on_disk = 0;
    size_t swapout_size;
    char *swap_buf;
    ssize_t swap_buf_len;
    int hdr_len = 0;
    if (mem == NULL)
	return;
    /* should we swap something out to disk? */
    debug(20, 7) ("storeSwapOut: %s\n", storeUrl(e));
    debug(20, 7) ("storeSwapOut: store_status = %s\n",
	storeStatusStr[e->store_status]);
    if (EBIT_TEST(e->flags, ENTRY_ABORTED)) {
	assert(EBIT_TEST(e->flags, RELEASE_REQUEST));
	storeSwapOutFileClose(e);
	return;
    }
    debug(20, 7) ("storeSwapOut: mem->inmem_lo = %d\n",
	(int) mem->inmem_lo);
    debug(20, 7) ("storeSwapOut: mem->inmem_hi = %d\n",
	(int) mem->inmem_hi);
    debug(20, 7) ("storeSwapOut: swapout.queue_offset = %d\n",
	(int) mem->swapout.queue_offset);
    if (mem->swapout.sio)
	debug(20, 7) ("storeSwapOut: storeOffset() = %d\n",
	    (int) storeOffset(mem->swapout.sio));
#if USE_ASYNC_IO
    if (mem->inmem_hi < mem->swapout.queue_offset) {
	storeAbort(e);
	assert(EBIT_TEST(e->flags, RELEASE_REQUEST));
	storeSwapOutFileClose(e);
	return;
    }
#else
    assert(mem->inmem_hi >= mem->swapout.queue_offset);
#endif
    lowest_offset = storeLowestMemReaderOffset(e);
    debug(20, 7) ("storeSwapOut: lowest_offset = %d\n",
	(int) lowest_offset);
    new_mem_lo = lowest_offset;
    assert(new_mem_lo >= mem->inmem_lo);
    /*
     * We should only free up to what we know has been written to
     * disk, not what has been queued for writing.  Otherwise there
     * will be a chunk of the data which is not in memory and is
     * not yet on disk.
     */
    if (storeSwapOutAble(e))
	if ((on_disk = storeSwapOutObjectBytesOnDisk(mem)) < new_mem_lo)
	    new_mem_lo = on_disk;
    stmemFreeDataUpto(&mem->data_hdr, new_mem_lo);
    mem->inmem_lo = new_mem_lo;
    if (e->swap_status == SWAPOUT_WRITING)
	assert(mem->inmem_lo <= on_disk);
    if (!storeSwapOutAble(e))
	return;
    swapout_size = (size_t) (mem->inmem_hi - mem->swapout.queue_offset);
    debug(20, 7) ("storeSwapOut: swapout_size = %d\n",
	(int) swapout_size);
    if (swapout_size == 0) {
#if OLD_CODE
	if (e->store_status == STORE_OK) {
	    debug(20, 1) ("storeSwapOut: nothing to write for STORE_OK\n");
	    storeSwapOutFileClose(e);
	}
#endif
	return;
    }
    if (e->store_status == STORE_PENDING) {
	/* wait for a full block to write */
	if (swapout_size < VM_WINDOW_SZ)
	    return;
	/*
	 * Wait until we are below the disk FD limit, only if the
	 * next server-side read won't be deferred.
	 */
	if (storeTooManyDiskFilesOpen() && !fwdCheckDeferRead(-1, e))
	    return;
    }
    /* Ok, we have stuff to swap out.  Is there a swapout.sio open? */
    if (e->swap_status == SWAPOUT_NONE) {
	assert(mem->swapout.sio == NULL);
	assert(mem->inmem_lo == 0);
	if (storeCheckCachable(e))
	    storeSwapOutStart(e);
	else
	    return;
	/* ENTRY_CACHABLE will be cleared and we'll never get
	 * here again */
    }
    assert(mem->swapout.sio != NULL);
    if (swapout_size > STORE_SWAP_BUF)
	swapout_size = STORE_SWAP_BUF;
    swap_buf = memAllocate(MEM_DISK_BUF);
    swap_buf_len = stmemCopy(&mem->data_hdr,
	mem->swapout.queue_offset,
	swap_buf,
	swapout_size);
    if (swap_buf_len < 0) {
	debug(20, 1) ("stmemCopy returned %d for '%s'\n", swap_buf_len, storeKeyText(e->key));
	storeUnlink(e->swap_file_number);
	storeDirMapBitReset(e->swap_file_number);
	e->swap_file_number = -1;
	e->swap_status = SWAPOUT_NONE;
	memFree(swap_buf, MEM_DISK_BUF);
	storeReleaseRequest(e);
	storeSwapOutFileClose(e);
	return;
    }
    debug(20, 3) ("storeSwapOut: swap_buf_len = %d\n", (int) swap_buf_len);
    assert(swap_buf_len > 0);
    debug(20, 3) ("storeSwapOut: swapping out %d bytes from %d\n",
	swap_buf_len, (int) mem->swapout.queue_offset);
    mem->swapout.queue_offset += swap_buf_len - hdr_len;
    storeWrite(mem->swapout.sio, swap_buf, swap_buf_len, -1, memFreeDISK);
    if (e->store_status == STORE_OK)
	if (mem->inmem_hi == mem->swapout.queue_offset)
	    storeSwapOutFileClose(e);
}

void
storeSwapOutFileClose(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    assert(mem != NULL);
    debug(20, 3) ("storeSwapOutFileClose: %s\n", storeKeyText(e->key));
    if (mem->swapout.sio == NULL)
	return;
    storeClose(mem->swapout.sio);
    mem->swapout.sio = NULL;
    storeUnlockObject(e);
}

static void
storeSwapOutFileClosed(void *data, int errflag, storeIOState * sio)
{
    generic_cbdata *c = data;
    StoreEntry *e = c->data;
    MemObject *mem = e->mem_obj;
    assert(e->swap_status == SWAPOUT_WRITING);
    cbdataFree(c);
    if (errflag) {
	debug(20, 1) ("storeSwapOutFileClosed: swapfile %08X, errflag=%d\n\t%s\n",
	    e->swap_file_number, errflag, xstrerror());
	storeDirMapBitReset(e->swap_file_number);
	/*
	 * yuck.  don't clear the filemap bit for some errors so that
	 * we don't try re-using it over and over
	 */
	if (errno != EPERM)
	    storeDirMapBitReset(e->swap_file_number);
	if (errflag == DISK_NO_SPACE_LEFT) {
	    storeDirDiskFull(e->swap_file_number);
	    storeDirConfigure();
	    storeConfigure();
	}
	e->swap_file_number = -1;
	e->swap_status = SWAPOUT_NONE;
	return;
    } else {
	/* swapping complete */
	debug(20, 3) ("storeSwapOutFileClosed: SwapOut complete: '%s' to %08X\n",
	    storeUrl(e), e->swap_file_number);
	e->swap_file_sz = objectLen(e) + mem->swap_hdr_sz;
	e->swap_status = SWAPOUT_DONE;
	storeDirUpdateSwapSize(e->swap_file_number, e->swap_file_sz, 1);
	if (storeCheckCachable(e)) {
	    storeLog(STORE_LOG_SWAPOUT, e);
	    storeDirSwapLog(e, SWAP_LOG_ADD);
	}
    }
    cbdataUnlock(sio);
}

/*
 * How much of the object data is on the disk?
 */
static off_t
storeSwapOutObjectBytesOnDisk(const MemObject * mem)
{
    /*
     * NOTE: storeOffset() represents the disk file size,
     * not the amount of object data on disk.
     * 
     * If we don't have at least 'swap_hdr_sz' bytes
     * then none of the object data is on disk.
     *
     * This should still be safe if swap_hdr_sz == 0,
     * meaning we haven't even opened the swapout file
     * yet.
     */
    off_t nwritten;
    if (mem->swapout.sio == NULL)
	return 0;
    nwritten = storeOffset(mem->swapout.sio);
    if (nwritten <= mem->swap_hdr_sz)
	return 0;
    return nwritten - mem->swap_hdr_sz;
}

/*
 * Is this entry a candidate for writing to disk?
 */
int
storeSwapOutAble(const StoreEntry * e)
{
    store_client *sc;
    if (e->mem_obj->swapout.sio != NULL)
	return 1;
    if (e->mem_obj->inmem_lo > 0)
	return 0;
    /*
     * If there are DISK clients, we must write to disk
     * even if its not cachable
     */
    for (sc = e->mem_obj->clients; sc; sc = sc->next)
	if (sc->type == STORE_DISK_CLIENT)
	    return 1;
    return EBIT_TEST(e->flags, ENTRY_CACHABLE);
}
