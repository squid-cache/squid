
/*
 * $Id: store_io_coss.cc,v 1.15 2002/06/26 09:55:57 hno Exp $
 *
 * DEBUG: section 81    Storage Manager COSS Interface
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
#include <aio.h>
#include "async_io.h"
#include "store_coss.h"

static DWCB storeCossWriteMemBufDone;
static DRCB storeCossReadDone;
static void storeCossIOCallback(storeIOState * sio, int errflag);
static char *storeCossMemPointerFromDiskOffset(SwapDir * SD, size_t offset, CossMemBuf ** mb);
static void storeCossMemBufLock(SwapDir * SD, storeIOState * e);
static void storeCossMemBufUnlock(SwapDir * SD, storeIOState * e);
static void storeCossWriteMemBuf(SwapDir * SD, CossMemBuf * t);
static void storeCossWriteMemBufDone(int fd, int errflag, size_t len, void *my_data);
static CossMemBuf *storeCossCreateMemBuf(SwapDir * SD, size_t start,
    sfileno curfn, int *collision);
static CBDUNL storeCossIOFreeEntry;

CBDATA_TYPE(storeIOState);
CBDATA_TYPE(CossMemBuf);

/* === PUBLIC =========================================================== */

/*
 * This routine sucks. I want to rewrite it when possible, and I also think
 * that we should check after creatmembuf() to see if the object has a
 * RELEASE_REQUEST set on it (thanks Eric!) rather than this way which seems
 * to work..
 * -- Adrian
 */
off_t
storeCossAllocate(SwapDir * SD, const StoreEntry * e, int which)
{
    CossInfo *cs = (CossInfo *) SD->fsdata;
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
    if ((cs->current_offset + allocsize) > (SD->max_size << 10)) {
	/*
	 * tried to allocate past the end of the disk, so wrap
	 * back to the beginning
	 */
	cs->current_membuf->flags.full = 1;
	cs->current_membuf->diskend = cs->current_offset - 1;
	cs->current_offset = 0;	/* wrap back to beginning */
	debug(81, 2) ("storeCossAllocate: wrap to 0\n");

	newmb = storeCossCreateMemBuf(SD, 0, checkf, &coll);
	cs->current_membuf = newmb;

	/* Check if we have overflowed the MemBuf */
    } else if ((cs->current_offset + allocsize) > cs->current_membuf->diskend) {
	/*
	 * Skip the blank space at the end of the stripe. start over.
	 */
	cs->current_membuf->flags.full = 1;
	cs->current_offset = cs->current_membuf->diskend + 1;
	debug(81, 2) ("storeCossAllocate: New offset - %ld\n",
	    (long int) cs->current_offset);
	newmb = storeCossCreateMemBuf(SD, cs->current_offset, checkf, &coll);
	cs->current_membuf = newmb;
    }
    /* If we didn't get a collision, then update the current offset and return it */
    if (coll == 0) {
	retofs = cs->current_offset;
	cs->current_offset = retofs + allocsize;
	return retofs;
    } else {
	debug(81, 3) ("storeCossAllocate: Collision\n");
	return -1;
    }
}

void
storeCossUnlink(SwapDir * SD, StoreEntry * e)
{
    debug(81, 3) ("storeCossUnlink: offset %d\n", e->swap_filen);
    storeCossRemove(SD, e);
}


storeIOState *
storeCossCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    CossState *cstate;
    storeIOState *sio;

    CBDATA_INIT_TYPE_FREECB(storeIOState, storeCossIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    cstate = memPoolAlloc(coss_state_pool);
    sio->fsstate = cstate;
    sio->offset = 0;
    sio->mode = O_WRONLY;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(e->mem_obj->object_sz != -1);

    /*
     * this one is kinda strange - Eric called storeCossAllocate(), then
     * storeCossOpen(O_RDONLY) .. weird. Anyway, I'm allocating this now.
     */
    sio->st_size = objectLen(e) + e->mem_obj->swap_hdr_sz;
    sio->swap_dirn = SD->index;
    sio->swap_filen = storeCossAllocate(SD, e, COSS_ALLOC_ALLOCATE);
    debug(81, 3) ("storeCossCreate: offset %d, size %ld, end %ld\n", sio->swap_filen, (long int) sio->st_size, (long int) (sio->swap_filen + sio->st_size));

    sio->callback = callback;
    sio->file_callback = file_callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = (StoreEntry *) e;

    cstate->flags.writing = 0;
    cstate->flags.reading = 0;
    cstate->readbuffer = NULL;
    cstate->reqdiskoffset = -1;

    /* Now add it into the index list */
    storeCossAdd(SD, e);

    storeCossMemBufLock(SD, sio);
    return sio;
}

storeIOState *
storeCossOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    storeIOState *sio;
    char *p;
    CossState *cstate;
    sfileno f = e->swap_filen;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    debug(81, 3) ("storeCossOpen: offset %d\n", f);

    CBDATA_INIT_TYPE_FREECB(storeIOState, storeCossIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    cstate = memPoolAlloc(coss_state_pool);

    sio->fsstate = cstate;
    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->offset = 0;
    sio->mode = O_RDONLY;
    sio->callback = callback;
    sio->file_callback = file_callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->st_size = e->swap_file_sz;
    sio->e = e;

    cstate->flags.writing = 0;
    cstate->flags.reading = 0;
    cstate->readbuffer = NULL;
    cstate->reqdiskoffset = -1;
    p = storeCossMemPointerFromDiskOffset(SD, f, NULL);
    /* make local copy so we don't have to lock membuf */
    if (p) {
	cstate->readbuffer = xmalloc(sio->st_size);
	xmemcpy(cstate->readbuffer, p, sio->st_size);
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
	sio->swap_filen = storeCossAllocate(SD, e, COSS_ALLOC_REALLOC);
	if (sio->swap_filen == -1) {
	    /* We have to clean up neatly .. */
	    cbdataFree(sio);
	    cs->numcollisions++;
	    debug(81, 2) ("storeCossOpen: Reallocation of %d/%d failed\n", e->swap_dirn, e->swap_filen);
	    /* XXX XXX XXX Will squid call storeUnlink for this object? */
	    return NULL;
	}
	/* Notify the upper levels that we've changed file number */
	sio->file_callback(sio->callback_data, 0, sio);

	/*
	 * lock the buffer so it doesn't get swapped out on us
	 * this will get unlocked in storeCossReadDone
	 */
	storeCossMemBufLock(SD, sio);

	/*
	 * Do the index magic to keep the disk and memory LRUs identical
	 */
	storeCossRemove(SD, e);
	storeCossAdd(SD, e);

	/*
	 * Since we've reallocated a spot for this object, we need to
	 * write it to the cossmembuf *and* return it in the read ..
	 */
	cstate->readbuffer = NULL;
    }
    return sio;
}

void
storeCossClose(SwapDir * SD, storeIOState * sio)
{
    debug(81, 3) ("storeCossClose: offset %d\n", sio->swap_filen);
    if (sio->mode == O_WRONLY)
	storeCossMemBufUnlock(SD, sio);
    storeCossIOCallback(sio, 0);
}

void
storeCossRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    char *p;
    CossState *cstate = (CossState *) sio->fsstate;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = cbdataReference(callback_data);
    debug(81, 3) ("storeCossRead: offset %ld\n", (long int) offset);
    sio->offset = offset;
    cstate->flags.reading = 1;
    if ((offset + size) > sio->st_size)
	size = sio->st_size - offset;
    cstate->requestlen = size;
    cstate->requestbuf = buf;
    cstate->requestoffset = offset;
    if (cstate->readbuffer == NULL) {
	p = storeCossMemPointerFromDiskOffset(SD, sio->swap_filen, NULL);
	/* Remember we need to translate the block offset to a disk offset! */
	a_file_read(&cs->aq, cs->fd,
	    p,
	    sio->st_size,
	    cstate->reqdiskoffset,
	    storeCossReadDone,
	    sio);
	cstate->reqdiskoffset = 0;	/* XXX */
    } else {
	storeCossReadDone(cs->fd,
	    cstate->readbuffer,
	    sio->st_size,
	    0,
	    sio);
    }
}

void
storeCossWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    char *dest;
    CossMemBuf *membuf;
    off_t diskoffset;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(sio->e->mem_obj->object_sz != -1);

    debug(81, 3) ("storeCossWrite: offset %ld, len %lu\n", (long int) sio->offset, (unsigned long int) size);
    diskoffset = sio->swap_filen + sio->offset;
    dest = storeCossMemPointerFromDiskOffset(SD, diskoffset, &membuf);
    assert(dest != NULL);
    xmemcpy(dest, buf, size);
    sio->offset += size;
    if (free_func)
	(free_func) (buf);
}


/*  === STATIC =========================================================== */

static void
storeCossReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
{
    storeIOState *sio = my_data;
    char *p;
    STRCB *callback = sio->read.callback;
    void *cbdata;
    SwapDir *SD = INDEXSD(sio->swap_dirn);
    CossState *cstate = (CossState *) sio->fsstate;
    size_t rlen;

    debug(81, 3) ("storeCossReadDone: fileno %d, FD %d, len %d\n",
	sio->swap_filen, fd, len);
    cstate->flags.reading = 0;
    if (errflag) {
	debug(81, 3) ("storeCossReadDone: got failure (%d)\n", errflag);
	rlen = -1;
    } else {
	if (cstate->readbuffer == NULL) {
	    cstate->readbuffer = xmalloc(sio->st_size);
	    p = storeCossMemPointerFromDiskOffset(SD, sio->swap_filen, NULL);
	    xmemcpy(cstate->readbuffer, p, sio->st_size);
	    storeCossMemBufUnlock(SD, sio);
	}
	sio->offset += len;
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
    CossState *cstate = (CossState *) sio->fsstate;
    STIOCB *callback = sio->callback;
    void *cbdata;
    debug(81, 3) ("storeCossIOCallback: errflag=%d\n", errflag);
    xfree(cstate->readbuffer);
    sio->callback = NULL;
    if (cbdataReferenceValidDone(sio->callback_data, &cbdata))
	callback(cbdata, errflag, sio);
    cbdataFree(sio);
}

static char *
storeCossMemPointerFromDiskOffset(SwapDir * SD, size_t offset, CossMemBuf ** mb)
{
    CossMemBuf *t;
    dlink_node *m;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
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
storeCossMemBufLock(SwapDir * SD, storeIOState * e)
{
    CossMemBuf *t;
    dlink_node *m;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
	if ((e->swap_filen >= t->diskstart) && (e->swap_filen <= t->diskend)) {
	    debug(81, 3) ("storeCossMemBufLock: locking %p, lockcount %d\n", t, t->lockcount);
	    t->lockcount++;
	    return;
	}
    }
    debug(81, 3) ("storeCossMemBufLock: FAILED to lock %p\n", e);
}

static void
storeCossMemBufUnlock(SwapDir * SD, storeIOState * e)
{
    CossMemBuf *t;
    dlink_node *m, *n;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    for (m = cs->membufs.head; m; m = n) {
	/*
	 * Note that storeCossWriteMemBuf() might call storeCossWriteMemBufDone
	 * immediately (if the write finishes immediately, of course!) which
	 * will make m = m->next kinda unworkable. So, get the next pointer.
	 */
	n = m->next;
	t = m->data;
	if ((e->swap_filen >= t->diskstart) && (e->swap_filen <= t->diskend)) {
	    t->lockcount--;
	    debug(81, 3) ("storeCossMemBufUnlock: unlocking %p, lockcount %d\n", t, t->lockcount);
	}
	if (t->flags.full && !t->flags.writing && !t->lockcount)
	    storeCossWriteMemBuf(SD, t);
    }
}

void
storeCossSync(SwapDir * SD)
{
    CossInfo *cs = (CossInfo *) SD->fsdata;
    CossMemBuf *t;
    dlink_node *m;
    int end;

    /* First, flush pending IO ops */
    a_file_syncqueue(&cs->aq);

    /* Then, flush any in-memory partial membufs */
    if (!cs->membufs.head)
	return;
    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
	if (t->flags.writing)
	    sleep(5);		/* XXX EEEWWW! */
	lseek(cs->fd, t->diskstart, SEEK_SET);
	end = (t == cs->current_membuf) ? cs->current_offset : t->diskend;
	FD_WRITE_METHOD(cs->fd, t->buffer, end - t->diskstart);
    }
}

static void
storeCossWriteMemBuf(SwapDir * SD, CossMemBuf * t)
{
    CossInfo *cs = (CossInfo *) SD->fsdata;
    debug(81, 3) ("storeCossWriteMemBuf: offset %ld, len %ld\n",
	(long int) t->diskstart, (long int) (t->diskend - t->diskstart));
    t->flags.writing = 1;
    /* Remember that diskstart/diskend are block offsets! */
    a_file_write(&cs->aq, cs->fd, t->diskstart, &t->buffer,
	t->diskend - t->diskstart, storeCossWriteMemBufDone, t, NULL);
}


static void
storeCossWriteMemBufDone(int fd, int errflag, size_t len, void *my_data)
{
    CossMemBuf *t = my_data;
    CossInfo *cs = (CossInfo *) t->SD->fsdata;

    debug(81, 3) ("storeCossWriteMemBufDone: buf %p, len %ld\n", t, (long int) len);
    if (errflag)
	debug(81, 0) ("storeCossMemBufWriteDone: got failure (%d)\n", errflag);

    dlinkDelete(&t->node, &cs->membufs);
    cbdataFree(t);
}

static CossMemBuf *
storeCossCreateMemBuf(SwapDir * SD, size_t start,
    sfileno curfn, int *collision)
{
    CossMemBuf *newmb, *t;
    StoreEntry *e;
    dlink_node *m, *prev;
    int numreleased = 0;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    CBDATA_INIT_TYPE_FREECB(CossMemBuf, NULL);
    newmb = cbdataAlloc(CossMemBuf);
    newmb->diskstart = start;
    debug(81, 3) ("storeCossCreateMemBuf: creating new membuf at %ld\n", (long int) newmb->diskstart);
    debug(81, 3) ("storeCossCreateMemBuf: at %p\n", newmb);
    newmb->diskend = newmb->diskstart + COSS_MEMBUF_SZ - 1;
    newmb->flags.full = 0;
    newmb->flags.writing = 0;
    newmb->lockcount = 0;
    newmb->SD = SD;
    /* XXX This should be reversed, with the new buffer last in the chain */
    dlinkAdd(newmb, &newmb->node, &cs->membufs);

    /* Print out the list of membufs */
    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
	debug(81, 3) ("storeCossCreateMemBuf: membuflist %ld lockcount %d\n", (long int) t->diskstart, t->lockcount);
    }

    /*
     * Kill objects from the tail to make space for a new chunk
     */
    for (m = cs->index.tail; m; m = prev) {
	prev = m->prev;
	e = m->data;
	if (curfn == e->swap_filen)
	    *collision = 1;	/* Mark an object alloc collision */
	if ((e->swap_filen >= newmb->diskstart) &&
	    (e->swap_filen <= newmb->diskend)) {
	    storeRelease(e);
	    numreleased++;
	} else
	    break;
    }
    if (numreleased > 0)
	debug(81, 3) ("storeCossCreateMemBuf: this allocation released %d storeEntries\n", numreleased);
    return newmb;
}

/*
 * Creates the initial membuf after rebuild
 */
void
storeCossStartMembuf(SwapDir * sd)
{
    CossInfo *cs = (CossInfo *) sd->fsdata;
    CossMemBuf *newmb = storeCossCreateMemBuf(sd, cs->current_offset, -1, NULL);
    assert(!cs->current_membuf);
    cs->current_membuf = newmb;
}

/*
 * Clean up any references from the SIO before it get's released.
 */
static void
storeCossIOFreeEntry(void *sio)
{
    memPoolFree(coss_state_pool, ((storeIOState *) sio)->fsstate);
}
