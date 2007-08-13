
/*
 * $Id: store_io_coss.cc,v 1.33 2007/08/13 17:20:56 hno Exp $
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
#include "CossSwapDir.h"
#include "Store.h"
#include "store_coss.h"
#include "MemObject.h"
#include "fde.h"
#include "SwapDir.h"
#include "StoreFScoss.h"
#include "DiskIO/DiskIOStrategy.h"

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
sfileno
CossSwapDir::allocate(const StoreEntry * e, int which)
{
    CossMemBuf *newmb;
    off_t retofs;
    off_t allocsize;
    int coll = 0;
    sfileno checkf;

    /* Make sure we chcek collisions if reallocating */

    if (which == COSS_ALLOC_REALLOC) {
        checkf = e->swap_filen;
        StoreFScoss::GetInstance().stats.alloc.realloc++;
    } else {
        checkf = -1;
        StoreFScoss::GetInstance().stats.alloc.alloc++;
    }

    if (e->swap_file_sz > 0)
        allocsize = e->swap_file_sz;
    else
        allocsize = e->objectLen() + e->mem_obj->swap_hdr_sz;

    /* Check if we have overflowed the disk .. */
    /* max_size is int, so cast to (off_t) *before* bit-shifting */
    if ((current_offset + allocsize) > ((off_t)max_size << 10)) {
        /*
         * tried to allocate past the end of the disk, so wrap
         * back to the beginning
         */
        StoreFScoss::GetInstance().stats.disk_overflows++;
        current_membuf->flags.full = 1;
        current_membuf->diskend = current_offset;
        current_membuf->maybeWrite(this);
        current_offset = 0;	/* wrap back to beginning */
        debugs(79, 2, "CossSwapDir::allocate: wrap to 0");

        newmb = createMemBuf(0, checkf, &coll);
        current_membuf = newmb;

        /* Check if we have overflowed the MemBuf */
    } else if ((current_offset + allocsize) >= current_membuf->diskend) {
        /*
         * Skip the blank space at the end of the stripe. start over.
         */
        StoreFScoss::GetInstance().stats.stripe_overflows++;
        current_membuf->flags.full = 1;
        current_offset = current_membuf->diskend;
        current_membuf->maybeWrite(this);
        debugs(79, 2, "CossSwapDir::allocate: New offset - " << current_offset);
        newmb = createMemBuf(current_offset, checkf, &coll);
        current_membuf = newmb;
    }

    /*
     * If we didn't get a collision, then update the current offset
     * and return it
     */
    if (coll == 0) {
        retofs = current_offset;
        current_offset = retofs + allocsize;
        /* round up to our blocksize */
        current_offset = ((current_offset + blksz_mask) >> blksz_bits ) << blksz_bits;
        return storeCossDiskOffsetToFileno(retofs);
    } else {
        StoreFScoss::GetInstance().stats.alloc.collisions++;
        debugs(79, 3, "CossSwapDir::allocate: Collision");
        return -1;
    }
}

void
CossSwapDir::unlink(StoreEntry & e)
{
    debugs(79, 3, "storeCossUnlink: offset " << e.swap_filen);
    StoreFScoss::GetInstance().stats.unlink.ops++;
    StoreFScoss::GetInstance().stats.unlink.success++;
    storeCossRemove(this, &e);
}

StoreIOState::Pointer
CossSwapDir::createStoreIO(StoreEntry &e, StoreIOState::STFNCB * file_callback, StoreIOState::STIOCB * callback, void *callback_data)
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
    StoreFScoss::GetInstance().stats.create.ops++;

    /*
     * this one is kinda strange - Eric called allocate(), then
     * storeCossOpen(O_RDONLY) .. weird. Anyway, I'm allocating this now.
     */
    cstate->st_size = e.objectLen() + e.mem_obj->swap_hdr_sz;
    sio->swap_dirn = index;
    sio->swap_filen = allocate(&e, COSS_ALLOC_ALLOCATE);
    debugs(79, 3, "storeCossCreate: offset " <<
           storeCossFilenoToDiskOffset(sio->swap_filen) <<
           ", size " << (long int) cstate->st_size << ", end " <<
           (sio->swap_filen + cstate->st_size));

    /* assume allocate() always succeeds */
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

    cstate->lockMemBuf();
    StoreFScoss::GetInstance().stats.create.success++;
    return sio;
}

StoreIOState::Pointer
CossSwapDir::openStoreIO(StoreEntry & e, StoreIOState::STFNCB * file_callback,
                         StoreIOState::STIOCB * callback, void *callback_data)
{
    char *p;
    CossState *cstate;
    sfileno f = e.swap_filen;

    debugs(79, 3, "storeCossOpen: offset " << f);
    StoreFScoss::GetInstance().stats.open.ops++;

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
    p = storeCossMemPointerFromDiskOffset(storeCossFilenoToDiskOffset(f), NULL);
    /* make local copy so we don't have to lock membuf */

    if (p) {
        cstate->readbuffer = (char *)xmalloc(cstate->st_size);
        xmemcpy(cstate->readbuffer, p, cstate->st_size);
        StoreFScoss::GetInstance().stats.open_mem_hits++;
    } else {
        /* Do the allocation */
        /* this is the first time we've been called on a new sio
         * read the whole object into memory, then return the 
         * requested amount
         */
        StoreFScoss::GetInstance().stats.open_mem_misses++;
        /*
         * This bit of code actually does the LRU disk thing - we realloc
         * a place for the object here, and the file_read() reads the object
         * into the cossmembuf for later writing ..
         */
        cstate->reqdiskoffset = storeCossFilenoToDiskOffset(sio->swap_filen);
        sio->swap_filen = -1;
        sio->swap_filen = allocate(&e, COSS_ALLOC_REALLOC);

        if (sio->swap_filen == -1) {
            /* We have to clean up neatly .. */
            StoreFScoss::GetInstance().stats.open.fail++;
            numcollisions++;
            debugs(79, 2, "storeCossOpen: Reallocation of " << e.swap_dirn << "/" << e.swap_filen << " failed");
            /* XXX XXX XXX Will squid call storeUnlink for this object? */
            return NULL;
        }

        /* Notify the upper levels that we've changed file number */
        sio->file_callback(sio->callback_data, 0, sio);

        /*
         * lock the buffer so it doesn't get swapped out on us
         * this will get unlocked in storeCossClose
         */
        cstate->lockMemBuf();

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

    StoreFScoss::GetInstance().stats.open.success++;
    return sio;
}

void
CossState::close()
{
    debugs(79, 3, "storeCossClose: offset " << swap_filen);

    StoreFScoss::GetInstance().stats.close.ops++;
    StoreFScoss::GetInstance().stats.close.success++;
    SD->storeCossMemBufUnlock(this);
    doCallback(0);
}

void
CossState::read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    char *p;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(swap_dirn);

    StoreFScoss::GetInstance().stats.read.ops++;
    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    read.callback = callback;
    read.callback_data = cbdataReference(callback_data);
    debugs(79, 3, "storeCossRead: offset " << offset);
    offset_ = offset;
    flags.reading = 1;

    if ((offset + (off_t)size) > st_size)
        size = st_size - offset;

    requestlen = size;

    requestbuf = buf;

    requestoffset = offset;

    if (readbuffer == NULL) {
        p = SD->storeCossMemPointerFromDiskOffset(SD->storeCossFilenoToDiskOffset(swap_filen), NULL);
        sfileno tempReqdiskoffset = reqdiskoffset;
        reqdiskoffset = 0;	/* XXX */
        SD->theFile->read(new CossRead(ReadRequest(p, st_size, tempReqdiskoffset), this));
    } else {
        /*
         * It was copied from memory in storeCossOpen()
         */
        ReadRequest::Pointer readRequest = new CossRead(ReadRequest(
                                               (char *)readbuffer,st_size, 0), this);
        SD->readCompleted(readbuffer, st_size, 0, readRequest);
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
    StoreFScoss::GetInstance().stats.write.ops++;

    debugs(79, 3, "storeCossWrite: offset " << offset_ << ", len " << (unsigned long int) size);
    diskoffset = SD->storeCossFilenoToDiskOffset(swap_filen) + offset_;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(swap_dirn);
    dest = SD->storeCossMemPointerFromDiskOffset(diskoffset, &membuf);
    assert(dest != NULL);
    xmemcpy(dest, buf, size);
    offset_ += size;

    if (free_func)
        (free_func) ((char *)buf);

    StoreFScoss::GetInstance().stats.write.success++;
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

CBDATA_CLASS_INIT(CossRead);
void *
CossRead::operator new (size_t)
{
    CBDATA_INIT_TYPE(CossRead);
    CossRead *result = cbdataAlloc(CossRead);
    return result;
}

void
CossRead::operator delete (void *address)
{
    cbdataFree(address);
}

CBDATA_CLASS_INIT(CossWrite);
void *
CossWrite::operator new (size_t)
{
    CBDATA_INIT_TYPE(CossWrite);
    CossWrite *result = cbdataAlloc(CossWrite);
    return result;
}

void
CossWrite::operator delete (void *address)
{
    cbdataFree(address);
}

void
CossState::doCallback(int errflag)
{
    STIOCB *callback = this->callback;
    void *cbdata;
    debugs(79, 3, "CossState::doCallback: errflag=" << errflag);
    assert(NULL == locked_membuf);
    xfree(readbuffer);
    this->callback = NULL;

    if (cbdataReferenceValidDone(callback_data, &cbdata))
        callback(cbdata, errflag, this);
}

char *
CossSwapDir::storeCossMemPointerFromDiskOffset(off_t offset, CossMemBuf ** mb)
{
    CossMemBuf *t;
    dlink_node *m;

    for (m = membufs.head; m; m = m->next) {
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

void
CossState::lockMemBuf()
{
    CossMemBuf *t = SD->storeCossFilenoToMembuf(swap_filen);
    debugs(79, 3, "CossState::lockMemBuf: locking " << t << ", lockcount " << t->lockcount);
    locked_membuf = t;
    ++t->lockcount;
}

void
CossSwapDir::storeCossMemBufUnlock(StoreIOState::Pointer sio)
{
    CossMemBuf *t = storeCossFilenoToMembuf(sio->swap_filen);
    CossState *cstate = dynamic_cast<CossState *>(sio.getRaw());

    if (NULL == t)
        return;

    debugs(79, 3, "storeCossMemBufUnlock: unlocking " << t << ", lockcount " << t->lockcount);

    t->lockcount--;

    cstate->locked_membuf = NULL;

    t->maybeWrite(this);
}

void
CossSwapDir::sync()
{
    CossMemBuf *t;
    dlink_node *m;
    off_t end;

    /* First, flush pending IO ops */
    io->sync();

    /* Then, flush any in-memory partial membufs */

    if (!membufs.head)
        return;

    for (m = membufs.head; m; m = m->next) {
        t = (CossMemBuf *)m->data;

        if (t->flags.writing) {
            debugs(79, 1, "WARNING: sleeping for 5 seconds in storeCossSync()");
            sleep(5);		/* XXX EEEWWW! */
        }

        end = (t == current_membuf) ? current_offset : t->diskend;

        if (end > t->diskstart)
            theFile->write(new CossWrite(WriteRequest((char const *)&t->buffer, t->diskstart, end - t->diskstart, NULL), t));

        /* and flush */
        io->sync();
    }
}

void
CossMemBuf::maybeWrite(CossSwapDir * SD)
{
    describe(3, __LINE__);

    if (!flags.full)
        debugs(79, 3, "membuf " << this << " not full");
    else if (flags.writing)
        debugs(79, 3, "membuf " << this << " writing");
    else if (lockcount)
        debugs(79, 3, "membuf " << this << " lockcount=" << lockcount);
    else
        write(SD);
}

void
CossMemBuf::write(CossSwapDir * SD)
{
    StoreFScoss::GetInstance().stats.stripe_write.ops++;
    debugs(79, 3, "CossMemBuf::write: offset " << diskstart << ", len " << (diskend - diskstart));
    flags.writing = 1;
    /* XXX Remember that diskstart/diskend are block offsets! */
    SD->theFile->write(new CossWrite(WriteRequest((char const *)&buffer, diskstart, diskend - diskstart, NULL), this));
}

CossMemBuf *
CossSwapDir::createMemBuf(off_t start, sfileno curfn, int *collision)
{
    CossMemBuf *newmb;
    CossMemBuf *t;
    StoreEntry *e;
    dlink_node *m, *prev;
    int numreleased = 0;

    CBDATA_INIT_TYPE_FREECB(CossMemBuf, NULL);
    newmb = cbdataAlloc(CossMemBuf);
    newmb->diskstart = start;
    debugs(79, 3, "CossSwapDir::createMemBuf: creating new membuf at " << newmb->diskstart);
    debugs(79, 3, "CossSwapDir::createMemBuf: at " << newmb);
    newmb->diskend = newmb->diskstart + COSS_MEMBUF_SZ;
    newmb->flags.full = 0;
    newmb->flags.writing = 0;
    newmb->lockcount = 0;
    newmb->SD = this;
    /* XXX This should be reversed, with the new buffer last in the chain */
    dlinkAdd(newmb, &newmb->node, &membufs);

    /* Print out the list of membufs */

    debugs(79, 3, "CossSwapDir::createMemBuf: membuflist:");

    for (m = membufs.head; m; m = m->next) {
        t = (CossMemBuf *)m->data;
        t->describe(3, __LINE__);
    }

    /*
     * Kill objects from the tail to make space for a new chunk
     */
    for (m = cossindex.tail; m; m = prev) {
        off_t o;
        prev = m->prev;
        e = (StoreEntry *)m->data;
        o = storeCossFilenoToDiskOffset(e->swap_filen);

        if (curfn == e->swap_filen)
            *collision = 1;	/* Mark an object alloc collision */

        if ((o >= (off_t)newmb->diskstart) && (o < (off_t)newmb->diskend)) {
            e->release();
            numreleased++;
        } else
            break;
    }

    if (numreleased > 0)
        debugs(79, 3, "CossSwapDir::createMemBuf: this allocation released " << numreleased << " storeEntries");

    StoreFScoss::GetInstance().stats.stripes++;

    return newmb;
}

/*
 * Creates the initial membuf after rebuild
 */
void
CossSwapDir::startMembuf()
{
    CossMemBuf *newmb;
    newmb = createMemBuf(current_offset, -1, NULL);
    assert(!current_membuf);
    current_membuf = newmb;
}

/*
 * Clean up any references from the SIO before it get's released.
 */
CossState::~CossState()
{}

void
CossMemBuf::describe(int level, int line)
{
     debugs(79, level, "membuf " << this << ", LC:" << std::setfill('0') <<  
            std::setw(2) << lockcount << ", ST:" << 
            std::setw(10) <<  (unsigned long) diskstart << ", FL:" << 
            (flags.full ? 'F' : '.') << (flags.writing ? 'W' : '.'));
}

