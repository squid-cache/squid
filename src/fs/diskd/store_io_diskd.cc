
/*
 * $Id: store_io_diskd.cc,v 1.23 2002/04/13 23:07:56 hno Exp $
 *
 * DEBUG: section 81    Squid-side DISKD I/O functions.
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

#include "config.h"
#include "squid.h"

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "store_diskd.h"

static int storeDiskdSend(int, SwapDir *, int, storeIOState *, int, int, off_t);
static void storeDiskdIOCallback(storeIOState * sio, int errflag);
static CBDUNL storeDiskdIOFreeEntry;

CBDATA_TYPE(storeIOState);

/* === PUBLIC =========================================================== */

storeIOState *
storeDiskdOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    sfileno f = e->swap_filen;
    int x;
    storeIOState *sio;
    char *buf;
    diskdstate_t *diskdstate;
    off_t shm_offset;
    diskdinfo_t *diskdinfo = SD->fsdata;
    debug(81, 3) ("storeDiskdOpen: fileno %08X\n", f);
    /*
     * Fail on open() if there are too many requests queued.
     */
    if (diskdinfo->away > diskdinfo->magic1) {
	debug(81, 3) ("storeDiskdOpen: FAILING, too many requests away\n");
	diskd_stats.open_fail_queue_len++;
	return NULL;
    }
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeDiskdIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    sio->fsstate = diskdstate = memPoolAlloc(diskd_state_pool);

    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_RDONLY;
    sio->callback = callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = e;

    diskdstate->flags.writing = 0;
    diskdstate->flags.reading = 0;
    diskdstate->flags.close_request = 0;
    diskdstate->id = diskd_stats.sio_id++;

    buf = storeDiskdShmGet(SD, &shm_offset);
    xstrncpy(buf, storeDiskdDirFullPath(SD, f, NULL), SHMBUF_BLKSZ);
    x = storeDiskdSend(_MQD_OPEN,
	SD,
	diskdstate->id,
	sio,
	strlen(buf) + 1,
	O_RDONLY,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend OPEN: %s\n", xstrerror());
	storeDiskdShmPut(SD, shm_offset);
	cbdataReferenceDone(sio->callback_data);
	cbdataFree(sio);
	return NULL;
    }
    diskd_stats.open.ops++;
    return sio;
}

storeIOState *
storeDiskdCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    sfileno f;
    int x;
    storeIOState *sio;
    char *buf;
    off_t shm_offset;
    diskdinfo_t *diskdinfo = SD->fsdata;
    diskdstate_t *diskdstate;
    /*
     * Fail on open() if there are too many requests queued.
     */
    if (diskdinfo->away > diskdinfo->magic1) {
	diskd_stats.open_fail_queue_len++;
	return NULL;
    }
    /* Allocate a number */
    f = storeDiskdDirMapBitAllocate(SD);
    debug(81, 3) ("storeDiskdCreate: fileno %08X\n", f);

    CBDATA_INIT_TYPE_FREECB(storeIOState, storeDiskdIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    sio->fsstate = diskdstate = memPoolAlloc(diskd_state_pool);

    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_WRONLY | O_CREAT | O_TRUNC;
    sio->callback = callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = e;

    diskdstate->flags.writing = 0;
    diskdstate->flags.reading = 0;
    diskdstate->flags.close_request = 0;
    diskdstate->id = diskd_stats.sio_id++;

    buf = storeDiskdShmGet(SD, &shm_offset);
    xstrncpy(buf, storeDiskdDirFullPath(SD, f, NULL), SHMBUF_BLKSZ);
    x = storeDiskdSend(_MQD_OPEN,
	SD,
	diskdstate->id,
	sio,
	strlen(buf) + 1,
	sio->mode,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend OPEN: %s\n", xstrerror());
	storeDiskdShmPut(SD, shm_offset);
	cbdataReferenceDone(sio->callback_data);
	cbdataFree(sio);
	return NULL;
    }
    storeDiskdDirReplAdd(SD, e);
    diskd_stats.create.ops++;
    return sio;
}


void
storeDiskdClose(SwapDir * SD, storeIOState * sio)
{
    int x;
    diskdstate_t *diskdstate = sio->fsstate;
    debug(81, 3) ("storeDiskdClose: dirno %d, fileno %08X\n", SD->index,
	sio->swap_filen);
    x = storeDiskdSend(_MQD_CLOSE,
	SD,
	diskdstate->id,
	sio,
	0,
	0,
	-1);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend CLOSE: %s\n", xstrerror());
	storeDiskdIOCallback(sio, DISK_ERROR);
    }
    diskdstate->flags.close_request = 1;
    diskd_stats.close.ops++;
}

void
storeDiskdRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    int x;
    off_t shm_offset;
    char *rbuf;
    diskdstate_t *diskdstate = sio->fsstate;
    debug(81, 3) ("storeDiskdRead: dirno %d, fileno %08X\n", sio->swap_dirn, sio->swap_filen);
    assert(!diskdstate->flags.close_request);
    if (!cbdataReferenceValid(sio))
	return;
    if (diskdstate->flags.reading) {
	debug(81, 1) ("storeDiskdRead: already reading!\n");
	return;
    }
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = cbdataReference(callback_data);
    diskdstate->read_buf = buf;	/* the one passed from above */
    sio->offset = offset;
    diskdstate->flags.reading = 1;
    rbuf = storeDiskdShmGet(SD, &shm_offset);
    assert(rbuf);
    x = storeDiskdSend(_MQD_READ,
	SD,
	diskdstate->id,
	sio,
	(int) size,
	(int) offset,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend READ: %s\n", xstrerror());
	storeDiskdShmPut(SD, shm_offset);
	storeDiskdIOCallback(sio, DISK_ERROR);
    }
    diskd_stats.read.ops++;
}

void
storeDiskdWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    int x;
    char *sbuf;
    off_t shm_offset;
    diskdstate_t *diskdstate = sio->fsstate;
    debug(81, 3) ("storeDiskdWrite: dirno %d, fileno %08X\n", SD->index, sio->swap_filen);
    assert(!diskdstate->flags.close_request);
    if (!cbdataReferenceValid(sio)) {
	free_func(buf);
	return;
    }
    diskdstate->flags.writing = 1;
    sbuf = storeDiskdShmGet(SD, &shm_offset);
    xmemcpy(sbuf, buf, size);
    if (free_func)
	free_func(buf);
    x = storeDiskdSend(_MQD_WRITE,
	SD,
	diskdstate->id,
	sio,
	(int) size,
	(int) offset,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend WRITE: %s\n", xstrerror());
	storeDiskdShmPut(SD, shm_offset);
	storeDiskdIOCallback(sio, DISK_ERROR);
    }
    diskd_stats.write.ops++;
}

void
storeDiskdUnlink(SwapDir * SD, StoreEntry * e)
{
    int x;
    off_t shm_offset;
    char *buf;
    diskdinfo_t *diskdinfo = SD->fsdata;

    debug(81, 3) ("storeDiskdUnlink: dirno %d, fileno %08X\n", SD->index,
	e->swap_filen);
    storeDiskdDirReplRemove(e);
    storeDiskdDirMapBitReset(SD, e->swap_filen);
    if (diskdinfo->away >= diskdinfo->magic1) {
	/* Damn, we need to issue a sync unlink here :( */
	debug(50, 2) ("storeDiskUnlink: Out of queue space, sync unlink\n");
	storeDiskdDirUnlinkFile(SD, e->swap_filen);
	return;
    }
    /* We can attempt a diskd unlink */
    buf = storeDiskdShmGet(SD, &shm_offset);
    xstrncpy(buf, storeDiskdDirFullPath(SD, e->swap_filen, NULL), SHMBUF_BLKSZ);
    x = storeDiskdSend(_MQD_UNLINK,
	SD,
	e->swap_filen,
	NULL,
	0,
	0,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend UNLINK: %s\n", xstrerror());
	unlink(buf);		/* XXX EWW! */
	storeDiskdShmPut(SD, shm_offset);
    }
    diskd_stats.unlink.ops++;
}


/*  === STATIC =========================================================== */

static void
storeDiskdOpenDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    statCounter.syscalls.disk.opens++;
    debug(81, 3) ("storeDiskdOpenDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	sio->mode == O_RDONLY ? diskd_stats.open.fail++ : diskd_stats.create.fail++;
	storeDiskdIOCallback(sio, DISK_ERROR);
    } else {
	sio->mode == O_RDONLY ? diskd_stats.open.success++ : diskd_stats.create.success++;
    }
}

static void
storeDiskdCloseDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    statCounter.syscalls.disk.closes++;
    debug(81, 3) ("storeDiskdCloseDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	diskd_stats.close.fail++;
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    diskd_stats.close.success++;
    storeDiskdIOCallback(sio, DISK_OK);
}

static void
storeDiskdReadDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    STRCB *callback = sio->read.callback;
    void *cbdata;
    SwapDir *sd = INDEXSD(sio->swap_dirn);
    diskdstate_t *diskdstate = sio->fsstate;
    diskdinfo_t *diskdinfo = sd->fsdata;
    char *their_buf = diskdstate->read_buf;
    char *sbuf;
    size_t len;
    statCounter.syscalls.disk.reads++;
    diskdstate->flags.reading = 0;
    debug(81, 3) ("storeDiskdReadDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	diskd_stats.read.fail++;
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    diskd_stats.read.success++;
    sbuf = diskdinfo->shm.buf + M->shm_offset;
    len = M->status;
    sio->offset += len;
    assert(callback);
    sio->read.callback = NULL;
    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata)) {
	assert(!diskdstate->flags.close_request);
	/*
	 * Only copy the data if the callback is still valid,
	 * if it isn't valid then the request should have been
	 * aborted.
	 *   -- adrian
	 */
	xmemcpy(their_buf, sbuf, len);	/* yucky copy */
	callback(cbdata, their_buf, len);
    }
}

static void
storeDiskdWriteDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    diskdstate_t *diskdstate = sio->fsstate;
    statCounter.syscalls.disk.writes++;
    diskdstate->flags.writing = 0;
    debug(81, 3) ("storeDiskdWriteDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	diskd_stats.write.fail++;
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    diskd_stats.write.success++;
    sio->offset += M->status;
}

static void
storeDiskdUnlinkDone(diomsg * M)
{
    debug(81, 3) ("storeDiskdUnlinkDone: fileno %08x status %d\n",
	M->id, M->status);
    statCounter.syscalls.disk.unlinks++;
    if (M->status < 0)
	diskd_stats.unlink.fail++;
    else
	diskd_stats.unlink.success++;
}

void
storeDiskdHandle(diomsg * M)
{
    if (cbdataReferenceValid(M->callback_data)) {
	switch (M->mtype) {
	case _MQD_OPEN:
	    storeDiskdOpenDone(M);
	    break;
	case _MQD_CLOSE:
	    storeDiskdCloseDone(M);
	    break;
	case _MQD_READ:
	    storeDiskdReadDone(M);
	    break;
	case _MQD_WRITE:
	    storeDiskdWriteDone(M);
	    break;
	case _MQD_UNLINK:
	    storeDiskdUnlinkDone(M);
	    break;
	default:
	    assert(0);
	    break;
	}
    } else {
	debug(81, 3) ("storeDiskdHandle: Invalid callback_data %p\n",
	    M->callback_data);
	/*
	 * The read operation has its own callback.  If we don't
	 * call storeDiskdReadDone(), then we must make sure the
	 * callback_data gets unlocked!
	 */
	if (_MQD_READ == M->mtype) {
	    /* XXX This cannot be the correct approach. This
	     * is most likely the wrong place for this. It should
	     * be done before the sio becomes invalid, not here.
	     */
	    storeIOState *sio = M->callback_data;
	    cbdataReferenceDone(sio->read.callback_data);
	}
    }
    cbdataReferenceDone(M->callback_data);
}

static void
storeDiskdIOCallback(storeIOState * sio, int errflag)
{
    void *cbdata;
    STIOCB *callback = sio->callback;
    debug(81, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    sio->callback = NULL;
    if (cbdataReferenceValidDone(sio->callback_data, &cbdata))
	callback(cbdata, errflag, sio);
    cbdataFree(sio);
}

static int
storeDiskdSend(int mtype, SwapDir * sd, int id, storeIOState * sio, int size, int offset, off_t shm_offset)
{
    int x;
    diomsg M;
    static int send_errors = 0;
    static int last_seq_no = 0;
    static int seq_no = 0;
    diskdinfo_t *diskdinfo = sd->fsdata;
    M.mtype = mtype;
    M.callback_data = cbdataReference(sio);
    M.size = size;
    M.offset = offset;
    M.status = -1;
    M.shm_offset = (int) shm_offset;
    M.id = id;
    M.seq_no = ++seq_no;
    if (M.seq_no < last_seq_no)
	debug(81, 1) ("WARNING: sequencing out of order\n");
    x = msgsnd(diskdinfo->smsgid, &M, msg_snd_rcv_sz, IPC_NOWAIT);
    last_seq_no = M.seq_no;
    if (0 == x) {
	diskd_stats.sent_count++;
	diskdinfo->away++;
    } else {
	debug(50, 1) ("storeDiskdSend: msgsnd: %s\n", xstrerror());
	cbdataReferenceDone(M.callback_data);
	assert(++send_errors < 100);
    }
    /*
     * We have to drain the queue here if necessary.  If we don't,
     * then we can have a lot of messages in the queue (probably
     * up to 2*magic1) and we can run out of shared memory buffers.
     */
    /*
     * Note that we call storeDirCallback (for all SDs), rather
     * than storeDiskdDirCallback for just this SD, so that while
     * we're "blocking" on this SD we can also handle callbacks
     * from other SDs that might be ready.
     */
    while (diskdinfo->away > diskdinfo->magic2) {
	struct timeval delay =
	{0, 1};
	select(0, NULL, NULL, NULL, &delay);
	storeDirCallback();
	if (delay.tv_usec < 1000000)
	    delay.tv_usec <<= 1;
    }
    return x;
}


/*
 * We can't pass memFree() as a free function here, because we need to free
 * the fsstate variable ..
 */
static void
storeDiskdIOFreeEntry(void *sio)
{
    memPoolFree(diskd_state_pool, ((storeIOState *) sio)->fsstate);
}
