
/*
 * $Id: store_io_coss.cc,v 1.25 2004/08/30 05:12:33 robertc Exp $
 *
 * DEBUG: section 79    Storage Manager COSS Interface
 * AUTHOR: Eric Stern
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
#include "Store.h"
#include <aio.h>
#include "async_io.h"
#include "store_coss.h"
#include "MemObject.h"
#include "fde.h"
#include "SwapDir.h"

static DWCB storeCossWriteMemBufDone;
static DRCB storeCossReadDone;
static void storeCossIOCallback(storeIOState * sio, int errflag);
static char *storeCossMemPointerFromDiskOffset(CossSwapDir * SD, size_t offset, CossMemBuf ** mb);
static void storeCossMemBufLock(CossSwapDir * SD, storeIOState * e);
static void storeCossMemBufUnlock(CossSwapDir * SD, storeIOState * e);
static void storeCossWriteMemBuf(CossSwapDir * SD, CossMemBuf * t);
static void storeCossWriteMemBufDone(int, int errflag, size_t len, void *my_data);
static CossMemBuf *storeCossCreateMemBuf(CossSwapDir * SD, size_t start,
        sfileno curfn, int *collision);
static void storeCossMaybeWriteMemBuf(CossSwapDir * SD, CossMemBuf * t);
static void storeCossMemBufDescribe(CossMemBuf * t, int level, int line);

CBDATA_TYPE(CossMemBuf);

/* === PUBLIC =========================================================== */

CossState::CossState(CossSwapDir *aCSD):SD (aCSD)
{}


/*
 * This routine sucks. I want to rewrite it when possible, and I also think
 * that we should check after creatmembuf() to see if the object has a
 * RELEASE_REQUEST set on it (thanks Eric!) rather than this way which seems
 * to work..
 * -- Adrian
 */
static sfileno
storeCossAllocate(CossSwapDir * SD, const StoreEntry * e, int which)
{
    CossMemBuf *newmb;
    off_t retofs;
    size_t allocsize;
    int coll = 0;
    sfileno checkf;

    /* Make sure we chcek collisions if reallocating */

    if (which == COSS_ALLOC_REALLOC) {
        checkf = e->swap_filen;
        coss_stats.alloc.realloc++;
    } else {
        checkf = -1;
        coss_stats.alloc.alloc++;
    }

    if (e->swap_file_sz > 0)
        allocsize = e->swap_file_sz;
    else
        allocsize = objectLen(e) + e->mem_obj->swap_hdr_sz;

    /* Since we're not supporting NOTIFY anymore, lets fail */
    assert(which != COSS_ALLOC_NOTIFY);

    /* Check if we have overflowed the disk .. */
    /* SD->max_size is int, so cast to (off_t) *before* bit-shifting */
    if ((off_t)(SD->current_offset + allocsize) > ((off_t)SD->max_size << 10)) {
        /*
         * tried to allocate past the end of the disk, so wrap
         * back to the beginning
         */
        coss_stats.disk_overflows++;
        SD->current_membuf->flags.full = 1;
        SD->current_membuf->diskend = SD->current_offset;
        storeCossMaybeWriteMemBuf(SD, SD->current_membuf);
        SD->current_offset = 0;	/* wrap back to beginning */
        debug(79, 2) ("storeCossAllocate: wrap to 0\n");

        newmb = storeCossCreateMemBuf(SD, 0, checkf, &coll);
        SD->current_membuf = newmb;

        /* Check if we have overflowed the MemBuf */
    } else if ((SD->current_offset + allocsize) >= SD->current_membuf->diskend) {
        /*
         * Skip the blank space at the end of the stripe. start over.
         */
        coss_stats.stripe_overflows++;
        SD->current_membuf->flags.full = 1;
        SD->current_offset = SD->current_membuf->diskend;
        storeCossMaybeWriteMemBuf(SD, SD->current_membuf);
        debug(79, 2) ("storeCossAllocate: New offset - %ld\n",
                      (long int) SD->current_offset);
        newmb = storeCossCreateMemBuf(SD, SD->current_offset, checkf, &coll);
        SD->current_membuf = newmb;
    }

    /*
     * If we didn't get a collision, then update the current offset
     * and return it
     */
    if (coll == 0) {
        retofs = SD->current_offset;
        SD->current_offset = retofs + allocsize;
        /* round up to our blocksize */
        SD->current_offset = ((SD->current_offset + SD->blksz_mask) >> SD->blksz_bits ) << SD->blksz_bits;
        return SD->storeCossDiskOffsetToFileno(retofs);
    } else {
        coss_stats.alloc.collisions++;
        debug(79, 3) ("storeCossAllocate: Collision\n");
        return -1;
    }
}

void
CossSwapDir::unlink(StoreEntry & e)
{
    debug(79, 3) ("storeCossUnlink: offset %d\n", e.swap_filen);
    coss_stats.unlink.ops++;
    coss_stats.unlink.success++;
    storeCossRemove(this, &e);
}

StoreIOState::Pointer
CossSwapDir::createStoreIO(StoreEntry &e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    CossState *cstate;
    StoreIOState::Pointer sio = new CossState(this);
    cstate = dynamic_cast<CossState *>(sio.getRaw());
    sio->offset_ = 0;
    sio->mode = O_WRONLY | O_BINARY;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(e.mem_obj->object_sz != -1);
    coss_stats.create.ops++;

    /*
     * this one is kinda strange - Eric called storeCossAllocate(), then
     * storeCossOpen(O_RDONLY) .. weird. Anyway, I'm allocating this now.
     */
    cstate->st_size = objectLen(&e) + e.mem_obj->swap_hdr_sz;
    sio->swap_dirn = index;
    sio->swap_filen = storeCossAllocate(this, &e, COSS_ALLOC_ALLOCATE);
    debug(79, 3) ("storeCossCreate: offset %ld, size %ld, end %ld\n",
                  (long int) storeCossFilenoToDiskOffset(sio->swap_filen),
                  (long int) cstate->st_size,
                  (long int) (sio->swap_filen + cstate->st_size));
    /* assume storeCossAllocate() always succeeds */
    assert(-1 != sio->swap_filen);

    sio->callback = callback;
    sio->file_callback = file_callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = &e;

    cstate->flags.writing = 0;
    cstate->flags.reading = 0;
    cstate->readbuffer = NULL;
    cstate->reqdiskoffset = -1;

    /* Now add it into the index list */
    storeCossAdd(this, &e);

    storeCossMemBufLock(this, sio.getRaw());
    coss_stats.create.success++;
    return sio;
}

StoreIOState::Pointer
CossSwapDir::openStoreIO(StoreEntry & e, STFNCB * file_callback,
                         STIOCB * callback, void *callback_data)
{
    char *p;
    CossState *cstate;
    sfileno f = e.swap_filen;

    debug(79, 3) ("storeCossOpen: offset %d\n", f);
    coss_stats.open.ops++;

    StoreIOState::Pointer sio = new CossState (this);
    cstate = dynamic_cast<CossState *>(sio.getRaw());

    sio->swap_filen = f;
    sio->swap_dirn = index;
    sio->offset_ = 0;
    sio->mode = O_RDONLY | O_BINARY;
    sio->callback = callback;
    sio->file_callback = file_callback;
    sio->callback_data = cbdataReference(callback_data);
    cstate->st_size = e.swap_file_sz;
    sio->e = &e;

    cstate->flags.writing = 0;
    cstate->flags.reading = 0;
    cstate->readbuffer = NULL;
    cstate->reqdiskoffset = -1;
    p = storeCossMemPointerFromDiskOffset(this, storeCossFilenoToDiskOffset(f), NULL);
    /* make local copy so we don't have to lock membuf */

    if (p) {
        cstate->readbuffer = (char *)xmalloc(cstate->st_size);
        xmemcpy(cstate->readbuffer, p, cstate->st_size);
        coss_stats.open_mem_hits++;
    } else {
        /* Do the allocation */
        /* this is the first time we've been called on a new sio
         * read the whole object into memory, then return the 
         * requested amount
         */
        coss_stats.open_mem_misses++;
        /*
         * This bit of code actually does the LRU disk thing - we realloc
         * a place for the object here, and the file_read() reads the object
         * into the cossmembuf for later writing ..
         */
        cstate->reqdiskoffset = storeCossFilenoToDiskOffset(sio->swap_filen);
        sio->swap_filen = -1;
        sio->swap_filen = storeCossAllocate(this, &e, COSS_ALLOC_REALLOC);

        if (sio->swap_filen == -1) {
            /* We have to clean up neatly .. */
            coss_stats.open.fail++;
            numcollisions++;
            debug(79, 2) ("storeCossOpen: Reallocation of %d/%d failed\n", e.swap_dirn, e.swap_filen);
            /* XXX XXX XXX Will squid call storeUnlink for this object? */
            return NULL;
        }

        /* Notify the upper levels that we've changed file number */
        sio->file_callback(sio->callback_data, 0, sio.getRaw());

        /*
         * lock the buffer so it doesn't get swapped out on us
         * this will get unlocked in storeCossClose
         */
        storeCossMemBufLock(this, sio.getRaw());

        /*
         * Do the index magic to keep the disk and memory LRUs identical
         */
        storeCossRemove(this, &e);

        storeCossAdd(this, &e);

        /*
        	 * NOTE cstate->readbuffer is NULL.  We'll actually read
        	 * the disk data into the MemBuf in storeCossRead() and
        	 * return that pointer back to the caller
         	 */
    }

    coss_stats.open.success++;
    return sio;
}

void
CossState::close()
{
    debug(79, 3) ("storeCossClose: offset %d\n", swap_filen);

    coss_stats.close.ops++;
    coss_stats.close.success++;
    storeCossMemBufUnlock(SD, this);
    storeCossIOCallback(this, 0);
}

void
CossState::read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    char *p;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(swap_dirn);

    coss_stats.read.ops++;
    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    read.callback = callback;
    read.callback_data = cbdataReference(callback_data);
    debug(79, 3) ("storeCossRead: offset %ld\n", (long int) offset);
    offset_ = offset;
    flags.reading = 1;

    if ((offset + size) > st_size)
        size = st_size - offset;

    requestlen = size;

    requestbuf = buf;

    requestoffset = offset;

    if (readbuffer == NULL) {
        p = storeCossMemPointerFromDiskOffset(SD, SD->storeCossFilenoToDiskOffset(swap_filen), NULL);
        a_file_read(&SD->aq, SD->fd,
                    p,
                    st_size,
                    reqdiskoffset,
                    storeCossReadDone,
                    this);
        reqdiskoffset = 0;	/* XXX */
    } else {
        /*
         * It was copied from memory in storeCossOpen()
         */
        storeCossReadDone(SD->fd,
                          readbuffer,
                          st_size,
                          0,
                          this);
    }
}

void
CossState::write(char const *buf, size_t size, off_t offset, FREE * free_func)
{
    char *dest;
    CossMemBuf *membuf;
    off_t diskoffset;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(e->mem_obj->object_sz != -1);
    coss_stats.write.ops++;

    debug(79, 3) ("storeCossWrite: offset %ld, len %lu\n", (long int) offset_, (unsigned long int) size);
    diskoffset = SD->storeCossFilenoToDiskOffset(swap_filen) + offset_;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(swap_dirn);
    dest = storeCossMemPointerFromDiskOffset(SD, diskoffset, &membuf);
    assert(dest != NULL);
    xmemcpy(dest, buf, size);
    offset_ += size;

    if (free_func)
        (free_func) ((char *)buf);

    coss_stats.write.success++;
}

off_t
CossSwapDir::storeCossFilenoToDiskOffset(sfileno f)
{
    return (off_t) f << blksz_bits;
}

sfileno
CossSwapDir::storeCossDiskOffsetToFileno(off_t o)
{
    assert(0 == (o & blksz_mask));
    return o >> blksz_bits;
}

CossMemBuf *
CossSwapDir::storeCossFilenoToMembuf(sfileno f)
{
    CossMemBuf *t = NULL;
    dlink_node *m;
    off_t o = storeCossFilenoToDiskOffset(f);

    for (m = membufs.head; m; m = m->next) {
        t = (CossMemBuf *)m->data;

        if ((o >= (off_t)t->diskstart) && (o < (off_t)t->diskend))
            break;
    }

    assert(t);
    return t;
}

/*  === STATIC =========================================================== */

static void
storeCossReadDone(int rvfd, const char *buf, int len, int errflag, void *my_data)
{
    storeIOState *sio = (storeIOState *)my_data;
    char *p;
    STRCB *callback = sio->read.callback;
    void *cbdata;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(sio->swap_dirn);
    CossState *cstate = dynamic_cast<CossState *>(sio);
    ssize_t rlen;

    debug(79, 3) ("storeCossReadDone: fileno %d, FD %d, len %d\n",
                  sio->swap_filen, rvfd, len);
    cstate->flags.reading = 0;

    if (errflag) {
        coss_stats.read.fail++;

        if (errflag > 0) {
            errno = errflag;
            debug(79, 1) ("storeCossReadDone: error: %s\n", xstrerror());
        } else {
            debug(79, 1) ("storeCossReadDone: got failure (%d)\n", errflag);
        }

        rlen = -1;
    } else {
        coss_stats.read.success++;

        if (cstate->readbuffer == NULL) {
            cstate->readbuffer = (char *)xmalloc(cstate->st_size);
            p = storeCossMemPointerFromDiskOffset(SD,
                                                  SD->storeCossFilenoToDiskOffset(sio->swap_filen),
                                                  NULL);
            xmemcpy(cstate->readbuffer, p, cstate->st_size);
        }

        sio->offset_ += len;
        xmemcpy(cstate->requestbuf, &cstate->readbuffer[cstate->requestoffset],
                cstate->requestlen);
        rlen = (size_t) cstate->requestlen;
    }

    assert(callback);
    sio->read.callback = NULL;

    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata))
        callback(cbdata, cstate->requestbuf, rlen);
}

static void
storeCossIOCallback(storeIOState * sio, int errflag)
{
    CossState *cstate = dynamic_cast<CossState *>(sio);
    STIOCB *callback = sio->callback;
    void *cbdata;
    debug(79, 3) ("storeCossIOCallback: errflag=%d\n", errflag);
    assert(NULL == cstate->locked_membuf);
    xfree(cstate->readbuffer);
    sio->callback = NULL;

    if (cbdataReferenceValidDone(sio->callback_data, &cbdata))
        callback(cbdata, errflag, sio);

    cbdataFree(sio);
}

static char *
storeCossMemPointerFromDiskOffset(CossSwapDir * SD, size_t offset, CossMemBuf ** mb)
{
    CossMemBuf *t;
    dlink_node *m;

    for (m = SD->membufs.head; m; m = m->next) {
        t = (CossMemBuf *)m->data;

        if ((offset >= t->diskstart) && (offset < t->diskend)) {
            if (mb)
                *mb = t;

            return &t->buffer[offset - t->diskstart];
        }
    }

    if (mb)
        *mb = NULL;

    return NULL;
}

static void
storeCossMemBufLock(CossSwapDir * SD, storeIOState * sio)
{
    CossMemBuf *t = SD->storeCossFilenoToMembuf(sio->swap_filen);
    CossState *cstate = dynamic_cast<CossState *>(sio);
    debug(79, 3) ("storeCossMemBufLock: locking %p, lockcount %d\n", t, t->lockcount);
    cstate->locked_membuf = t;
    t->lockcount++;
}

static void
storeCossMemBufUnlock(CossSwapDir * SD, storeIOState * sio)
{
    CossMemBuf *t = SD->storeCossFilenoToMembuf(sio->swap_filen);
    CossState *cstate = dynamic_cast<CossState *>(sio);

    if (NULL == t)
        return;

    debug(79, 3) ("storeCossMemBufUnlock: unlocking %p, lockcount %d\n", t, t->lockcount);

    t->lockcount--;

    cstate->locked_membuf = NULL;

    storeCossMaybeWriteMemBuf(SD, t);
}

void
CossSwapDir::sync()
{
    CossMemBuf *t;
    dlink_node *m;
    int end;

    /* First, flush pending IO ops */
    a_file_syncqueue(&aq);

    /* Then, flush any in-memory partial membufs */

    if (!membufs.head)
        return;

    for (m = membufs.head; m; m = m->next) {
        t = (CossMemBuf *)m->data;

        if (t->flags.writing) {
            debug(79, 1) ("WARNING: sleeping for 5 seconds in storeCossSync()\n");
            sleep(5);		/* XXX EEEWWW! */
        }

        lseek(fd, t->diskstart, SEEK_SET);

        end = (t == current_membuf) ? current_offset : t->diskend;

        FD_WRITE_METHOD(fd, t->buffer, end - t->diskstart);
    }
}

static void
storeCossMaybeWriteMemBuf(CossSwapDir * SD, CossMemBuf * t)
{
    storeCossMemBufDescribe(t, 3, __LINE__);

    if (!t->flags.full)
        debug(79, 3) ("membuf %p not full\n", t);
    else if (t->flags.writing)
        debug(79, 3) ("membuf %p writing\n", t);
    else if (t->lockcount)
        debug(79, 3) ("membuf %p lockcount=%d\n", t, t->lockcount);
    else
        storeCossWriteMemBuf(SD, t);
}

static void
storeCossWriteMemBuf(CossSwapDir * SD, CossMemBuf * t)
{
    coss_stats.stripe_write.ops++;
    debug(79, 3) ("storeCossWriteMemBuf: offset %ld, len %ld\n",
                  (long int) t->diskstart, (long int) (t->diskend - t->diskstart));
    t->flags.writing = 1;
    a_file_write(&SD->aq, SD->fd, t->diskstart, &t->buffer,
                 t->diskend - t->diskstart, storeCossWriteMemBufDone, t, NULL);
}


static void
storeCossWriteMemBufDone(int rvfd, int errflag, size_t len, void *my_data)
{
    CossMemBuf *t = (CossMemBuf *)my_data;

    debug(79, 3) ("storeCossWriteMemBufDone: buf %p, len %ld\n", t, (long int) len);

    if (errflag) {
        coss_stats.stripe_write.fail++;
        debug(79, 1) ("storeCossWriteMemBufDone: got failure (%d)\n", errflag);
        debug(79, 1) ("FD %d, size=%x\n", rvfd, t->diskend - t->diskstart);
    } else {
        coss_stats.stripe_write.success++;
    }


    dlinkDelete(&t->node, &t->SD->membufs);
    cbdataFree(t);
    coss_stats.stripes--;
}

static CossMemBuf *
storeCossCreateMemBuf(CossSwapDir * SD, size_t start,
                      sfileno curfn, int *collision)
{
    CossMemBuf *newmb;
    CossMemBuf *t;
    StoreEntry *e;
    dlink_node *m, *prev;
    int numreleased = 0;

    CBDATA_INIT_TYPE_FREECB(CossMemBuf, NULL);
    newmb = cbdataAlloc(CossMemBuf);
    newmb->diskstart = start;
    debug(79, 3) ("storeCossCreateMemBuf: creating new membuf at %ld\n", (long int) newmb->diskstart);
    debug(79, 3) ("storeCossCreateMemBuf: at %p\n", newmb);
    newmb->diskend = newmb->diskstart + COSS_MEMBUF_SZ;
    newmb->flags.full = 0;
    newmb->flags.writing = 0;
    newmb->lockcount = 0;
    newmb->SD = SD;
    /* XXX This should be reversed, with the new buffer last in the chain */
    dlinkAdd(newmb, &newmb->node, &SD->membufs);

    /* Print out the list of membufs */

    debug(79, 3) ("storeCossCreateMemBuf: membuflist:\n");

    for (m = SD->membufs.head; m; m = m->next) {
        t = (CossMemBuf *)m->data;
        storeCossMemBufDescribe(t, 3, __LINE__);
    }

    /*
     * Kill objects from the tail to make space for a new chunk
     */
    for (m = SD->cossindex.tail; m; m = prev) {
        off_t o;
        prev = m->prev;
        e = (StoreEntry *)m->data;
        o = SD->storeCossFilenoToDiskOffset(e->swap_filen);

        if (curfn == e->swap_filen)
            *collision = 1;	/* Mark an object alloc collision */

        if ((o >= (off_t)newmb->diskstart) && (o < (off_t)newmb->diskend)) {
            storeRelease(e);
            numreleased++;
        } else
            break;
    }

    if (numreleased > 0)
        debug(79, 3) ("storeCossCreateMemBuf: this allocation released %d storeEntries\n", numreleased);

    coss_stats.stripes++;

    return newmb;
}

/*
 * Creates the initial membuf after rebuild
 */
void
storeCossStartMembuf(CossSwapDir * sd)
{
    CossMemBuf *newmb;
    newmb = storeCossCreateMemBuf(sd, sd->current_offset, -1, NULL);
    assert(!sd->current_membuf);
    sd->current_membuf = newmb;
}

/*
 * Clean up any references from the SIO before it get's released.
 */
CossState::~CossState()
{}

static void
storeCossMemBufDescribe(CossMemBuf * t, int level, int line)
{
    debug(79, level) ("membuf %p, LC:%02d, ST:%010lu, FL:%c%c\n",
                      t,
                      t->lockcount,
                      (unsigned long) t->diskstart,
                      t->flags.full ? 'F' : '.',
                      t->flags.writing ? 'W' : '.');
}

