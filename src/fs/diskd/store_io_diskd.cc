
#include "config.h"
#include "squid.h"
#include "store_diskd.h"

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#undef assert
#include <assert.h>


/*
 * DEBUG: section 81  Diskd Interface functions
 */


static int storeDiskdSend(int, SwapDir *, int, storeIOState *, int, int, int);
static void storeDiskdIOCallback(storeIOState * sio, int errflag);
static void storeDiskdIOFreeEntry(void *sio, int foo);

/*
 * SHMBUFS is the number of shared memory buffers to allocate for
 * Each SwapDir.
 */
#define SHMBUFS 96
#define SHMBUF_BLKSZ SM_PAGE_SIZE


/* === PUBLIC =========================================================== */

storeIOState *
storeDiskdOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    sfileno f = e->swap_filen;
    int x;
    storeIOState *sio;
    char *buf;
    int shm_offset;
    diskdinfo_t *diskdinfo = (diskdinfo_t *) SD->fsdata;
    debug(81, 3) ("storeDiskdOpen: fileno %08X\n", f);
    /*
     * XXX Eventually there should be an option here to fail on open()
     * If there are too many requests queued.
     */
    if (diskdinfo->away > diskdinfo->magic1) {
	debug(81, 3) ("storeDiskdOpen: FAILING, too many requests away\n");
	diskd_stats.open_fail_queue_len++;
	return NULL;
    }
    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, storeDiskdIOFreeEntry, MEM_STORE_IO);
    sio->fsstate = memPoolAlloc(diskd_state_pool);

    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_RDONLY;
    sio->callback = callback;
    sio->callback_data = callback_data;
    sio->e = e;
    cbdataLock(callback_data);

    ((diskdstate_t *) (sio->fsstate))->flags.writing = 0;
    ((diskdstate_t *) (sio->fsstate))->flags.reading = 0;
    ((diskdstate_t *) (sio->fsstate))->flags.close_request = 0;
    ((diskdstate_t *) (sio->fsstate))->id = diskd_stats.sio_id++;

    buf = storeDiskdShmGet(SD, &shm_offset);
    /* XXX WRONG!!! :) */
    strcpy(buf, storeDiskdDirFullPath(SD, f, NULL));
    x = storeDiskdSend(_MQD_OPEN,
	SD,
	((diskdstate_t *) (sio->fsstate))->id,
	sio,
	strlen(buf) + 1,
	O_RDONLY,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend OPEN: %s\n", xstrerror());
	storeDiskdShmPut(SD, shm_offset);
	cbdataUnlock(sio->callback_data);
	cbdataFree(sio);
	return NULL;
    }
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
    int shm_offset;
    diskdinfo_t *diskdinfo = (diskdinfo_t *) SD->fsdata;
    /*
     * XXX Eventually there should be an option here to fail on open()
     * If there are too many requests queued.
     */
    if (diskdinfo->away > diskdinfo->magic1) {
	diskd_stats.open_fail_queue_len++;
	return NULL;
    }
    /* Allocate a number */
    f = storeDiskdDirMapBitAllocate(SD);
    debug(81, 3) ("storeDiskdCreate: fileno %08X\n", f);

    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, storeDiskdIOFreeEntry, MEM_STORE_IO);
    sio->fsstate = memPoolAlloc(diskd_state_pool);

    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_WRONLY | O_CREAT | O_TRUNC;
    sio->callback = callback;
    sio->callback_data = callback_data;
    sio->e = e;
    cbdataLock(callback_data);

    ((diskdstate_t *) (sio->fsstate))->flags.writing = 0;
    ((diskdstate_t *) (sio->fsstate))->flags.reading = 0;
    ((diskdstate_t *) (sio->fsstate))->flags.close_request = 0;
    ((diskdstate_t *) (sio->fsstate))->id = diskd_stats.sio_id++;

    buf = storeDiskdShmGet(SD, &shm_offset);
    /* XXX WRONG!!! :) */
    strcpy(buf, storeDiskdDirFullPath(SD, f, NULL));
    x = storeDiskdSend(_MQD_OPEN,
	SD,
	((diskdstate_t *) (sio->fsstate))->id,
	sio,
	strlen(buf) + 1,
	sio->mode,
	shm_offset);
    if (x < 0) {
	debug(50, 1) ("storeDiskdSend OPEN: %s\n", xstrerror());
	storeDiskdShmPut(SD, shm_offset);
	cbdataUnlock(sio->callback_data);
	cbdataFree(sio);
	return NULL;
    }
    storeDiskdDirReplAdd(SD, e);
    return sio;
}


void
storeDiskdClose(SwapDir * SD, storeIOState * sio)
{
    int x;
    diskdstate_t *diskdstate = (diskdstate_t *) sio->fsstate;
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
}

void
storeDiskdRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    int x;
    int shm_offset;
    char *rbuf;
    diskdstate_t *diskdstate = (diskdstate_t *) sio->fsstate;
    if (!cbdataValid(sio))
	return;
    if (diskdstate->flags.reading) {
	debug(81, 1) ("storeDiskdRead: already reading!\n");
	return;
    }
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = callback_data;
    diskdstate->read_buf = buf;	/* the one passed from above */
    cbdataLock(sio->read.callback_data);
    debug(81, 3) ("storeDiskdRead: dirno %d, fileno %08X\n", sio->swap_dirn, sio->swap_filen);
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
}

void
storeDiskdWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    int x;
    char *sbuf;
    int shm_offset;
    diskdstate_t *diskdstate = (diskdstate_t *) sio->fsstate;
    debug(81, 3) ("storeDiskdWrite: dirno %d, fileno %08X\n", SD->index, sio->swap_filen);
    if (!cbdataValid(sio)) {
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
}

void
storeDiskdUnlink(SwapDir * SD, StoreEntry * e)
{
    int x;
    int shm_offset;
    char *buf;
    diskdinfo_t *diskdinfo = (diskdinfo_t *) SD->fsdata;

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
    strcpy(buf, storeDiskdDirFullPath(SD, e->swap_filen, NULL));
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
}


/*  === STATIC =========================================================== */

static void
storeDiskdOpenDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    Counter.syscalls.disk.opens++;
    debug(81, 3) ("storeDiskdOpenDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
    }
}

static void
storeDiskdCloseDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    Counter.syscalls.disk.closes++;
    debug(81, 3) ("storeDiskdCloseDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    storeDiskdIOCallback(sio, DISK_OK);
}

static void
storeDiskdReadDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    STRCB *callback = sio->read.callback;
    SwapDir *sd = INDEXSD(sio->swap_dirn);
    diskdstate_t *diskdstate = sio->fsstate;
    diskdinfo_t *diskdinfo = sd->fsdata;
    void *their_data = sio->read.callback_data;
    char *their_buf = diskdstate->read_buf;
    char *sbuf;
    size_t len;
    int valid;
    Counter.syscalls.disk.reads++;
    diskdstate->flags.reading = 0;
    valid = cbdataValid(sio->read.callback_data);
    cbdataUnlock(sio->read.callback_data);
    debug(81, 3) ("storeDiskdReadDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    sbuf = diskdinfo->shm.buf + M->shm_offset;
    len = M->status;
    xmemcpy(their_buf, sbuf, len);	/* yucky copy */
    sio->offset += len;
    assert(callback);
    assert(their_data);
    sio->read.callback = NULL;
    sio->read.callback_data = NULL;
    if (valid)
	callback(their_data, their_buf, len);
}

static void
storeDiskdWriteDone(diomsg * M)
{
    storeIOState *sio = M->callback_data;
    diskdstate_t *diskdstate = (diskdstate_t *) sio->fsstate;
    Counter.syscalls.disk.writes++;
    diskdstate->flags.writing = 0;
    debug(81, 3) ("storeDiskdWriteDone: dirno %d, fileno %08x status %d\n",
	sio->swap_dirn, sio->swap_filen, M->status);
    if (M->status < 0) {
	storeDiskdIOCallback(sio, DISK_ERROR);
	return;
    }
    sio->offset += M->status;
}

static void
storeDiskdUnlinkDone(diomsg * M)
{
    debug(81, 3) ("storeDiskdUnlinkDone: fileno %08x status %d\n",
	M->id, M->status);
    Counter.syscalls.disk.unlinks++;
}

void
storeDiskdHandle(diomsg * M)
{
    int valid = M->callback_data ? cbdataValid(M->callback_data) : 1;
    if (M->callback_data)
	cbdataUnlock(M->callback_data);
    if (!valid) {
	debug(81, 3) ("storeDiskdHandle: Invalid callback_data %p\n",
	    M->callback_data);
	/*
	 * The read operation has its own callback.  If we don't
	 * call storeDiskdReadDone(), then we must make sure the
	 * callback_data gets unlocked!
	 */
	if (_MQD_READ == M->mtype) {
	    storeIOState *sio = M->callback_data;
	    cbdataUnlock(sio->read.callback_data);
	}
	return;
    }
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
}

static void
storeDiskdIOCallback(storeIOState * sio, int errflag)
{
    int valid = cbdataValid(sio->callback_data);
    debug(81, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    cbdataUnlock(sio->callback_data);
    if (valid)
	sio->callback(sio->callback_data, errflag, sio);
    cbdataFree(sio);
}

static int
storeDiskdSend(int mtype, SwapDir * sd, int id, storeIOState * sio, int size, int offset, int shm_offset)
{
    int x;
    diomsg M;
    static int send_errors = 0;
    static int last_seq_no = 0;
    static int seq_no = 0;
    diskdinfo_t *diskdinfo = (diskdinfo_t *) sd->fsdata;
    M.mtype = mtype;
    M.callback_data = sio;
    M.size = size;
    M.offset = offset;
    M.status = -1;
    M.shm_offset = shm_offset;
    M.id = id;
    M.seq_no = ++seq_no;
    if (M.callback_data)
	cbdataLock(M.callback_data);
    if (M.seq_no < last_seq_no)
	debug(81, 1) ("WARNING: sequencing out of order\n");
    x = msgsnd(diskdinfo->smsgid, &M, msg_snd_rcv_sz, IPC_NOWAIT);
    last_seq_no = M.seq_no;
    if (0 == x) {
	diskd_stats.sent_count++;
	diskdinfo->away++;
    } else {
	debug(50, 1) ("storeDiskdSend: msgsnd: %s\n", xstrerror());
	if (M.callback_data)
	    cbdataUnlock(M.callback_data);
	assert(++send_errors < 100);
    }
    /*
     * We have to drain the queue here if necessary.  If we don't,
     * then we can have a lot of messages in the queue (probably
     * up to 2*magic1) and we can run out of shared memory buffers.
     */
    if (diskdinfo->away > diskdinfo->magic2)
	storeDiskdDirCallback(sd);
    return x;
}


/*
 * We can't pass memFree() as a free function here, because we need to free
 * the fsstate variable ..
 */
static void
storeDiskdIOFreeEntry(void *sio, int foo)
{
    memPoolFree(diskd_state_pool, ((storeIOState *) sio)->fsstate);
    memFree(sio, MEM_STORE_IO);
}
