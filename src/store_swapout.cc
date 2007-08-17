
/*
 * $Id: store_swapout.cc,v 1.120 2007/08/16 22:03:32 hno Exp $
 *
 * DEBUG: section 20    Storage Manager Swapout Functions
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
#include "cbdata.h"
#include "StoreClient.h"
#include "Store.h"
/* FIXME: Abstract the use of this more */
#include "mem_node.h"
#include "MemObject.h"
#include "SwapDir.h"

static void storeSwapOutStart(StoreEntry * e);
static StoreIOState::STIOCB storeSwapOutFileClosed;
static StoreIOState::STFNCB storeSwapOutFileNotify;

/* start swapping object to disk */
static void
storeSwapOutStart(StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    StoreIOState::Pointer sio;
    assert(mem);
    /* Build the swap metadata, so the filesystem will know how much
     * metadata there is to store
     */
    debugs(20, 5, "storeSwapOutStart: Begin SwapOut '" << e->url() << "' to dirno " <<  
           e->swap_dirn << ", fileno " << std::hex << std::setw(8) << std::setfill('0') << 
           std::uppercase << e->swap_filen);
    e->swap_status = SWAPOUT_WRITING;
    /* If we start swapping out objects with OutOfBand Metadata,
     * then this code needs changing
     */
    /* Create the swap file */
    generic_cbdata *c = new generic_cbdata(e);
    sio = storeCreate(e, storeSwapOutFileNotify, storeSwapOutFileClosed, c);

    if (sio == NULL) {
        e->swap_status = SWAPOUT_NONE;
        delete c;
        storeLog(STORE_LOG_SWAPOUTFAIL, e);
        return;
    }

    mem->swapout.sio = sio;
    /* Don't lock until after create, or the replacement
     * code might get confused */

    e->lock()

    ;
    /* Pick up the file number if it was assigned immediately */
    e->swap_filen = mem->swapout.sio->swap_filen;

    e->swap_dirn = mem->swapout.sio->swap_dirn;

    /* write out the swap metadata */
    /* TODO: make some sort of data,size refcounted immutable buffer
     * for use by this sort of function.
     */
    char const *buf = e->getSerialisedMetaData ();

    /* If we start swapping out with out of band metadata, this assert
     * will catch it - this code needs to be adjusted if that happens
     */
    assert (buf);

    storeIOWrite(mem->swapout.sio, buf, mem->swap_hdr_sz, 0, xfree);
}

static void
storeSwapOutFileNotify(void *data, int errflag, StoreIOState::Pointer self)
{
    generic_cbdata *c = (generic_cbdata *)data;
    StoreEntry *e = (StoreEntry *)c->data;
    MemObject *mem = e->mem_obj;
    assert(e->swap_status == SWAPOUT_WRITING);
    assert(mem);
    assert(mem->swapout.sio == self);
    assert(errflag == 0);
    e->swap_filen = mem->swapout.sio->swap_filen;
    e->swap_dirn = mem->swapout.sio->swap_dirn;
}

static void
doPages(StoreEntry *anEntry)
{
    MemObject *mem = anEntry->mem_obj;

    do {
        /*
         * Evil hack time.
         * We are paging out to disk in page size chunks. however, later on when
         * we update the queue position, we might not have a page (I *think*),
         * so we do the actual page update here.
         */

        if (mem->swapout.memnode == NULL) {
            /* We need to swap out the first page */
            mem->swapout.memnode = const_cast<mem_node *>(mem->data_hdr.start());
        } else {
            /* We need to swap out the next page */
            /* 20030636 RBC - we don't have ->next anymore.
             * But we do have the next location */
            mem->swapout.memnode = mem->data_hdr.getBlockContainingLocation (mem->swapout.memnode->end());
        }

        /*
         * Get the length of this buffer. We are assuming(!) that the buffer
         * length won't change on this buffer, or things are going to be very
         * strange. I think that after the copy to a buffer is done, the buffer
         * size should stay fixed regardless so that this code isn't confused,
         * but we can look at this at a later date or whenever the code results
         * in bad swapouts, whichever happens first. :-)
         */
        ssize_t swap_buf_len = mem->swapout.memnode->nodeBuffer.length;

        debugs(20, 3, "storeSwapOut: swap_buf_len = " << swap_buf_len);

        assert(swap_buf_len > 0);

        debugs(20, 3, "storeSwapOut: swapping out " << swap_buf_len << " bytes from " << mem->swapout.queue_offset);

        mem->swapout.queue_offset += swap_buf_len;

        storeIOWrite(mem->swapout.sio,
                     mem->data_hdr.NodeGet(mem->swapout.memnode),
                     swap_buf_len,
                     -1,
                     memNodeWriteComplete);

        /* the storeWrite() call might generate an error */
        if (anEntry->swap_status != SWAPOUT_WRITING)
            break;

        int64_t swapout_size = mem->endOffset() - mem->swapout.queue_offset;

        if (anEntry->store_status == STORE_PENDING)
            if (swapout_size < SM_PAGE_SIZE)
                break;

        if (swapout_size <= 0)
            return;
    } while (true);
}


/* This routine is called every time data is sent to the client side.
 * It's overhead is therefor, significant.
 */
void
StoreEntry::swapOut()
{
    if (!mem_obj)
        return;

    if (!swapoutPossible())
        return;

    debugs(20, 7, HERE << "storeSwapOut: mem->inmem_lo = " << mem_obj->inmem_lo);
    debugs(20, 7, HERE << "storeSwapOut: mem->endOffset() = " << mem_obj->endOffset());
    debugs(20, 7, HERE << "storeSwapOut: swapout.queue_offset = " << mem_obj->swapout.queue_offset);

    if (mem_obj->swapout.sio != NULL)
    debugs(20, 7, "storeSwapOut: storeOffset() = " << mem_obj->swapout.sio->offset()  );

    int64_t swapout_maxsize = mem_obj->endOffset() - mem_obj->swapout.queue_offset;

    assert(swapout_maxsize >= 0);

    int64_t const lowest_offset = mem_obj->lowestMemReaderOffset();

    debugs(20, 7, HERE << "storeSwapOut: lowest_offset = " << lowest_offset);

    /*
     * Grab the swapout_size and check to see whether we're going to defer
     * the swapout based upon size
     */
    if ((store_status != STORE_OK) && (swapout_maxsize < store_maxobjsize)) {
        /*
         * NOTE: the store_maxobjsize here is the max of optional
         * max-size values from 'cache_dir' lines.  It is not the
         * same as 'maximum_object_size'.  By default, store_maxobjsize
         * will be set to -1.  However, I am worried that this
         * deferance may consume a lot of memory in some cases.
         * It would be good to make this decision based on reply
         * content-length, rather than wait to accumulate huge
         * amounts of object data in memory.
         */
        debugs(20, 5, "storeSwapOut: Deferring starting swapping out");
        return;
    }

    trimMemory();
#if SIZEOF_OFF_T <= 4

    if (mem_obj->endOffset() > 0x7FFF0000) {
        debugs(20, 0, "WARNING: preventing off_t overflow for " << url());
        abort();
        return;
    }

#endif
    if (swap_status == SWAPOUT_WRITING)
        assert(mem_obj->inmem_lo <=  mem_obj->objectBytesOnDisk() );

    if (!swapOutAble())
        return;

    debugs(20, 7, "storeSwapOut: swapout_size = " << swapout_maxsize);

    if (swapout_maxsize == 0) {
        if (store_status == STORE_OK)
            swapOutFileClose();

        return;			/* Nevermore! */
    }

    if (store_status == STORE_PENDING) {
        /* wait for a full block to write */

        if (swapout_maxsize < SM_PAGE_SIZE)
            return;

        /*
         * Wait until we are below the disk FD limit, only if the
         * next server-side read won't be deferred.
         */
        if (storeTooManyDiskFilesOpen() && !checkDeferRead(-1))
            return;
    }

    /* Ok, we have stuff to swap out.  Is there a swapout.sio open? */
    if (swap_status == SWAPOUT_NONE) {
        assert(mem_obj->swapout.sio == NULL);
        assert(mem_obj->inmem_lo == 0);

        if (checkCachable())
            storeSwapOutStart(this);
        else
            return;

        /* ENTRY_CACHABLE will be cleared and we'll never get here again */
    }

    if (mem_obj->swapout.sio == NULL)
        return;

    doPages(this);

    if (mem_obj->swapout.sio == NULL)
        /* oops, we're not swapping out any more */
        return;

    if (store_status == STORE_OK) {
        /*
         * If the state is STORE_OK, then all data must have been given
         * to the filesystem at this point because storeSwapOut() is
         * not going to be called again for this entry.
         */
        assert(mem_obj->endOffset() == mem_obj->swapout.queue_offset);
        swapOutFileClose();
    }
}

void
StoreEntry::swapOutFileClose()
{
    assert(mem_obj != NULL);
    debugs(20, 3, "storeSwapOutFileClose: " << getMD5Text());
    debugs(20, 3, "storeSwapOutFileClose: sio = " << mem_obj->swapout.sio.getRaw());

    if (mem_obj->swapout.sio == NULL)
        return;

    storeClose(mem_obj->swapout.sio);
}

static void
storeSwapOutFileClosed(void *data, int errflag, StoreIOState::Pointer self)
{
    generic_cbdata *c = (generic_cbdata *)data;
    StoreEntry *e = (StoreEntry *)c->data;
    MemObject *mem = e->mem_obj;
    assert(mem->swapout.sio == self);
    assert(e->swap_status == SWAPOUT_WRITING);
    cbdataFree(c);

    if (errflag) {
        debugs(20, 1, "storeSwapOutFileClosed: dirno " << e->swap_dirn << ", swapfile " << 
               std::hex << std::setw(8) << std::setfill('0') << std::uppercase << 
               e->swap_filen << ", errflag=" << errflag);
        debugs(20, 1, "\t" << xstrerror());

        if (errflag == DISK_NO_SPACE_LEFT) {
            /* FIXME: this should be handle by the link from store IO to
             * Store, rather than being a top level API call.
             */
            e->store()->diskFull();
            storeConfigure();
        }

        if (e->swap_filen > 0)
            e->unlink();

        e->swap_filen = -1;

        e->swap_dirn = -1;

        e->swap_status = SWAPOUT_NONE;

        e->releaseRequest();
    } else {
        /* swapping complete */
        debugs(20, 3, "storeSwapOutFileClosed: SwapOut complete: '" << e->url() << "' to " << 
               e->swap_dirn  << ", " << std::hex << std::setw(8) << std::setfill('0') << 
               std::uppercase << e->swap_filen);
        e->swap_file_sz = e->objectLen() + mem->swap_hdr_sz;
        e->swap_status = SWAPOUT_DONE;
        e->store()->updateSize(e->swap_file_sz, 1);

        if (e->checkCachable()) {
            storeLog(STORE_LOG_SWAPOUT, e);
            storeDirSwapLog(e, SWAP_LOG_ADD);
        }

        statCounter.swap.outs++;
    }

    debugs(20, 3, "storeSwapOutFileClosed: " << __FILE__ << ":" << __LINE__);
    mem->swapout.sio = NULL;
    e->unlock();
}

/*
 * Is this entry a candidate for writing to disk?
 */
bool
StoreEntry::swapOutAble() const
{
    dlink_node *node;

    if (mem_obj->swapout.sio != NULL)
        return true;

    if (mem_obj->inmem_lo > 0)
        return false;

    /*
     * If there are DISK clients, we must write to disk
     * even if its not cachable
     * RBC: Surely we should not create disk client on non cacheable objects?
     * therefore this should be an assert?
     * RBC 20030708: We can use disk to avoid mem races, so this shouldn't be
     * an assert.
     */
    for (node = mem_obj->clients.head; node; node = node->next) {
        if (((store_client *) node->data)->getType() == STORE_DISK_CLIENT)
            return true;
    }

    /* Don't pollute the disk with icons and other special entries */
    if (EBIT_TEST(flags, ENTRY_SPECIAL))
        return false;

    if (!EBIT_TEST(flags, ENTRY_CACHABLE))
        return false;

    if (!mem_obj->isContiguous())
        return false;

    return true;
}
