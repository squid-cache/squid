
/*
 * $Id: store_io_coss.cc,v 1.20 2002/12/27 10:26:36 robertc Exp $
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

CBDATA_TYPE(CossMemBuf);

/* === PUBLIC =========================================================== */

MemPool *CossState::Pool = NULL; 

void *
CossState::operator new (size_t)
{
    if (!Pool)
	Pool = memPoolCreate("Squid COSS State Data", sizeof (CossState));
    return memPoolAlloc(Pool);
}
 
void
CossState::operator delete (void *address)
{
    memPoolFree (Pool, address);
}
    
CossState::CossState(CossSwapDir *aCSD):SD (aCSD)
{
}


/*
 * This routine sucks. I want to rewrite it when possible, and I also think
 * that we should check after creatmembuf() to see if the object has a
 * RELEASE_REQUEST set on it (thanks Eric!) rather than this way which seems
 * to work..
 * -- Adrian
 */
off_t
storeCossAllocate(CossSwapDir * SD, const StoreEntry * e, int which)
{
    CossMemBuf *newmb;
    off_t retofs;
    size_t allocsize;
    int coll = 0;
    sfileno checkf;

    /* Make sure we chcek collisions if reallocating */
    if (which == COSS_ALLOC_REALLOC)
	checkf = e->swap_filen;
    else
	checkf = -1;

    retofs = e->swap_filen;	/* Just for defaults, or while rebuilding */

    if (e->swap_file_sz > 0)
	allocsize = e->swap_file_sz;
    else
	allocsize = objectLen(e) + e->mem_obj->swap_hdr_sz;

    /* Since we're not supporting NOTIFY anymore, lets fail */
    assert(which != COSS_ALLOC_NOTIFY);

    /* Check if we have overflowed the disk .. */
    if ((SD->current_offset + allocsize) > (size_t)(SD->max_size << 10)) {
	/*
	 * tried to allocate past the end of the disk, so wrap
	 * back to the beginning
	 */
	SD->current_membuf->flags.full = 1;
	SD->current_membuf->diskend = SD->current_offset - 1;
	SD->current_offset = 0;	/* wrap back to beginning */
	debug(79, 2) ("storeCossAllocate: wrap to 0\n");

	newmb = storeCossCreateMemBuf(SD, 0, checkf, &coll);
	SD->current_membuf = newmb;

	/* Check if we have overflowed the MemBuf */
    } else if ((SD->current_offset + allocsize) > SD->current_membuf->diskend) {
	/*
	 * Skip the blank space at the end of the stripe. start over.
	 */
	SD->current_membuf->flags.full = 1;
	SD->current_offset = SD->current_membuf->diskend + 1;
	debug(79, 2) ("storeCossAllocate: New offset - %ld\n",
	    (long int) SD->current_offset);
	newmb = storeCossCreateMemBuf(SD, SD->current_offset, checkf, &coll);
	SD->current_membuf = newmb;
    }
    /* If we didn't get a collision, then update the current offset and return it */
    if (coll == 0) {
	retofs = SD->current_offset;
	SD->current_offset = retofs + allocsize;
	return retofs;
    } else {
	debug(79, 3) ("storeCossAllocate: Collision\n");
	return -1;
    }
}

void
CossSwapDir::unlink(StoreEntry & e)
{
    debug(79, 3) ("storeCossUnlink: offset %d\n", e.swap_filen);
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

    /*
     * this one is kinda strange - Eric called storeCossAllocate(), then
     * storeCossOpen(O_RDONLY) .. weird. Anyway, I'm allocating this now.
     */
    cstate->st_size = objectLen(&e) + e.mem_obj->swap_hdr_sz;
    sio->swap_dirn = index;
    sio->swap_filen = storeCossAllocate(this, &e, COSS_ALLOC_ALLOCATE);
    debug(79, 3) ("storeCossCreate: offset %d, size %ld, end %ld\n", sio->swap_filen, (long int) cstate->st_size, (long int) (sio->swap_filen + cstate->st_size));

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
    p = storeCossMemPointerFromDiskOffset(this, f, NULL);
    /* make local copy so we don't have to lock membuf */
    if (p) {
	cstate->readbuffer = (char *)xmalloc(cstate->st_size);
	xmemcpy(cstate->readbuffer, p, cstate->st_size);
    } else {
	/* Do the allocation */
	/* this is the first time we've been called on a new sio
	 * read the whole object into memory, then return the 
	 * requested amount
	 */
	/*
	 * This bit of code actually does the LRU disk thing - we realloc
	 * a place for the object here, and the file_read() reads the object
	 * into the cossmembuf for later writing ..
	 */
	cstate->reqdiskoffset = sio->swap_filen;
	sio->swap_filen = -1;
	sio->swap_filen = storeCossAllocate(this, &e, COSS_ALLOC_REALLOC);
	if (sio->swap_filen == -1) {
	    /* We have to clean up neatly .. */
	    numcollisions++;
	    debug(79, 2) ("storeCossOpen: Reallocation of %d/%d failed\n", e.swap_dirn, e.swap_filen);
	    /* XXX XXX XXX Will squid call storeUnlink for this object? */
	    return NULL;
	}
	/* Notify the upper levels that we've changed file number */
	sio->file_callback(sio->callback_data, 0, sio.getRaw());

	/*
	 * lock the buffer so it doesn't get swapped out on us
	 * this will get unlocked in storeCossReadDone
	 */
	storeCossMemBufLock(this, sio.getRaw());

	/*
	 * Do the index magic to keep the disk and memory LRUs identical
	 */
	storeCossRemove(this, &e);
	storeCossAdd(this, &e);

	/*
	 * Since we've reallocated a spot for this object, we need to
	 * write it to the cossmembuf *and* return it in the read ..
	 */
	cstate->readbuffer = NULL;
    }
    return sio;
}

void
CossState::close()
{
    debug(79, 3) ("storeCossClose: offset %d\n", swap_filen);
    if (FILE_MODE(mode) == O_WRONLY)
	storeCossMemBufUnlock(SD, this);
    storeCossIOCallback(this, 0);
}

void
CossState::read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    char *p;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(swap_dirn);

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
	p = storeCossMemPointerFromDiskOffset(SD, swap_filen, NULL);
	/* Remember we need to translate the block offset to a disk offset! */
	a_file_read(&SD->aq, SD->fd,
	    p,
	    st_size,
	    reqdiskoffset,
	    storeCossReadDone,
	    this);
	reqdiskoffset = 0;	/* XXX */
    } else {
	storeCossReadDone(SD->fd,
	    readbuffer,
	    st_size,
	    0,
	    this);
    }
}

void
CossState::write(char *buf, size_t size, off_t offset, FREE * free_func)
{
    char *dest;
    CossMemBuf *membuf;
    off_t diskoffset;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(e->mem_obj->object_sz != -1);

    debug(79, 3) ("storeCossWrite: offset %ld, len %lu\n", (long int) offset_, (unsigned long int) size);
    diskoffset = swap_filen + offset_;
    CossSwapDir *SD = (CossSwapDir *)INDEXSD(swap_dirn);
    dest = storeCossMemPointerFromDiskOffset(SD, diskoffset, &membuf);
    assert(dest != NULL);
    xmemcpy(dest, buf, size);
    offset_ += size;
    if (free_func)
	(free_func) (buf);
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
	debug(79, 3) ("storeCossReadDone: got failure (%d)\n", errflag);
	rlen = -1;
    } else {
	if (cstate->readbuffer == NULL) {
	    cstate->readbuffer = (char *)xmalloc(cstate->st_size);
	    p = storeCossMemPointerFromDiskOffset(SD, sio->swap_filen, NULL);
	    xmemcpy(cstate->readbuffer, p, cstate->st_size);
	    storeCossMemBufUnlock(SD, sio);
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
	if ((offset >= t->diskstart) && (offset <= t->diskend)) {
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
storeCossMemBufLock(CossSwapDir * SD, storeIOState * e)
{
    CossMemBuf *t;
    dlink_node *m;

    for (m = SD->membufs.head; m; m = m->next) {
	t = (CossMemBuf *)m->data;
	if (((size_t)e->swap_filen >= t->diskstart) && ((size_t)e->swap_filen <= t->diskend)) {
	    debug(79, 3) ("storeCossMemBufLock: locking %p, lockcount %d\n", t, t->lockcount);
	    t->lockcount++;
	    return;
	}
    }
    debug(79, 3) ("storeCossMemBufLock: FAILED to lock %p\n", e);
}

static void
storeCossMemBufUnlock(CossSwapDir * SD, storeIOState * e)
{
    CossMemBuf *t;
    dlink_node *m, *n;

    for (m = SD->membufs.head; m; m = n) {
	/*
	 * Note that storeCossWriteMemBuf() might call storeCossWriteMemBufDone
	 * immediately (if the write finishes immediately, of course!) which
	 * will make m = m->next kinda unworkable. So, get the next pointer.
	 */
	n = m->next;
	t = (CossMemBuf *)m->data;
	if (((size_t)e->swap_filen >= t->diskstart) && ((size_t)e->swap_filen <= t->diskend)) {
	    t->lockcount--;
	    debug(79, 3) ("storeCossMemBufUnlock: unlocking %p, lockcount %d\n", t, t->lockcount);
	}
	if (t->flags.full && !t->flags.writing && !t->lockcount)
	    storeCossWriteMemBuf(SD, t);
    }
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
	if (t->flags.writing)
	    sleep(5);		/* XXX EEEWWW! */
	lseek(fd, t->diskstart, SEEK_SET);
	end = (t == current_membuf) ? current_offset : t->diskend;
	FD_WRITE_METHOD(fd, t->buffer, end - t->diskstart);
    }
}

static void
storeCossWriteMemBuf(CossSwapDir * SD, CossMemBuf * t)
{
    debug(79, 3) ("storeCossWriteMemBuf: offset %ld, len %ld\n",
	(long int) t->diskstart, (long int) (t->diskend - t->diskstart));
    t->flags.writing = 1;
    /* Remember that diskstart/diskend are block offsets! */
    a_file_write(&SD->aq, SD->fd, t->diskstart, &t->buffer,
	t->diskend - t->diskstart, storeCossWriteMemBufDone, t, NULL);
}


static void
storeCossWriteMemBufDone(int rvfd, int errflag, size_t len, void *my_data)
{
    CossMemBuf *t = (CossMemBuf *)my_data;

    debug(79, 3) ("storeCossWriteMemBufDone: buf %p, len %ld\n", t, (long int) len);
    if (errflag)
	debug(79, 0) ("storeCossMemBufWriteDone: got failure (%d)\n", errflag);

    dlinkDelete(&t->node, &t->SD->membufs);
    cbdataFree(t);
}

static CossMemBuf *
storeCossCreateMemBuf(CossSwapDir * SD, size_t start,
    sfileno curfn, int *collision)
{
    CossMemBuf *newmb, *t;
    StoreEntry *e;
    dlink_node *m, *prev;
    int numreleased = 0;

    CBDATA_INIT_TYPE_FREECB(CossMemBuf, NULL);
    newmb = cbdataAlloc(CossMemBuf);
    newmb->diskstart = start;
    debug(79, 3) ("storeCossCreateMemBuf: creating new membuf at %ld\n", (long int) newmb->diskstart);
    debug(79, 3) ("storeCossCreateMemBuf: at %p\n", newmb);
    newmb->diskend = newmb->diskstart + COSS_MEMBUF_SZ - 1;
    newmb->flags.full = 0;
    newmb->flags.writing = 0;
    newmb->lockcount = 0;
    newmb->SD = SD;
    /* XXX This should be reversed, with the new buffer last in the chain */
    dlinkAdd(newmb, &newmb->node, &SD->membufs);

    /* Print out the list of membufs */
    for (m = SD->membufs.head; m; m = m->next) {
	t = (CossMemBuf *)m->data;
	debug(79, 3) ("storeCossCreateMemBuf: membuflist %ld lockcount %d\n", (long int) t->diskstart, t->lockcount);
    }

    /*
     * Kill objects from the tail to make space for a new chunk
     */
    for (m = SD->cossindex.tail; m; m = prev) {
	prev = m->prev;
	e = (StoreEntry *)m->data;
	if (curfn == e->swap_filen)
	    *collision = 1;	/* Mark an object alloc collision */
	if (((size_t)e->swap_filen >= newmb->diskstart) &&
	    ((size_t)e->swap_filen <= newmb->diskend)) {
	    storeRelease(e);
	    numreleased++;
	} else
	    break;
    }
    if (numreleased > 0)
	debug(79, 3) ("storeCossCreateMemBuf: this allocation released %d storeEntries\n", numreleased);
    return newmb;
}

/*
 * Creates the initial membuf after rebuild
 */
void
storeCossStartMembuf(CossSwapDir * sd)
{
    CossMemBuf *newmb = storeCossCreateMemBuf(sd, sd->current_offset, -1, NULL);
    assert(!sd->current_membuf);
    sd->current_membuf = newmb;
}

/*
 * Clean up any references from the SIO before it get's released.
 */
CossState::~CossState()
{
}
