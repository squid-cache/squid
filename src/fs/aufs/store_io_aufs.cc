
/*
 * DEBUG 78
 */

#include "squid.h"
#include "store_asyncufs.h"

static AIOCB storeAufsReadDone;
static AIOCB storeAufsWriteDone;
static void storeAufsIOCallback(storeIOState * sio, int errflag);
static AIOCB storeAufsOpenDone;
static int storeAufsSomethingPending(storeIOState *);
static int storeAufsKickWriteQueue(storeIOState * sio);
static void storeAufsIOFreeEntry(void *, int);

struct _queued_write {
    char *buf;
    size_t size;
    off_t offset;
    FREE *free_func;
};

struct _queued_read {
    char *buf;
    size_t size;
    off_t offset;
    STRCB *callback;
    void *callback_data;
};

/* === PUBLIC =========================================================== */

/* open for reading */
storeIOState *
storeAufsOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    sfileno f = e->swap_filen;
    char *path = storeAufsDirFullPath(SD, f, NULL);
    storeIOState *sio;
    debug(78, 3) ("storeAufsOpen: fileno %08X\n", f);
    /*
     * we should detect some 'too many files open' condition and return
     * NULL here.
     */
    while (aioQueueSize() > MAGIC1)
	return NULL;
    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, storeAufsIOFreeEntry, MEM_STORE_IO);
    sio->fsstate = memPoolAlloc(aio_state_pool);
    ((aiostate_t *) (sio->fsstate))->fd = -1;
    ((aiostate_t *) (sio->fsstate))->flags.opening = 1;
    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_RDONLY;
    sio->callback = callback;
    sio->callback_data = callback_data;
    sio->e = e;
    cbdataLock(callback_data);
    aioOpen(path, O_RDONLY, 0644, storeAufsOpenDone, sio);
    Opening_FD++;
    store_open_disk_fd++;
    return sio;
}

/* open for creating */
storeIOState *
storeAufsCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    char *path;
    storeIOState *sio;
    sfileno filn;
    sdirno dirn;

    /* Allocate a number */
    dirn = SD->index;
    filn = storeAufsDirMapBitAllocate(SD);
    path = storeAufsDirFullPath(SD, filn, NULL);

    debug(78, 3) ("storeAufsCreate: fileno %08X\n", filn);
    /*
     * we should detect some 'too many files open' condition and return
     * NULL here.
     */
    while (aioQueueSize() > MAGIC1)
	return NULL;
    sio = memAllocate(MEM_STORE_IO);
    cbdataAdd(sio, storeAufsIOFreeEntry, MEM_STORE_IO);
    sio->fsstate = memPoolAlloc(aio_state_pool);
    ((aiostate_t *) (sio->fsstate))->fd = -1;
    ((aiostate_t *) (sio->fsstate))->flags.opening = 1;
    sio->swap_filen = filn;
    sio->swap_dirn = dirn;
    sio->mode = O_WRONLY;
    sio->callback = callback;
    sio->callback_data = callback_data;
    sio->e = (StoreEntry *) e;
    cbdataLock(callback_data);
    aioOpen(path, O_WRONLY | O_CREAT | O_TRUNC, 0644, storeAufsOpenDone, sio);
    Opening_FD++;
    store_open_disk_fd++;

    /* now insert into the replacement policy */
    storeAufsDirReplAdd(SD, e);
    return sio;

}



/* Close */
void
storeAufsClose(SwapDir * SD, storeIOState * sio)
{
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    debug(78, 3) ("storeAufsClose: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, aiostate->fd);
    if (storeAufsSomethingPending(sio)) {
	aiostate->flags.close_request = 1;
	return;
    }
    storeAufsIOCallback(sio, 0);
}


/* Read */
void
storeAufsRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    assert(!aiostate->flags.reading);
    if (aiostate->fd < 0) {
	struct _queued_read *q;
	debug(78, 3) ("storeAufsRead: queueing read because FD < 0\n");
	assert(aiostate->flags.opening);
	assert(aiostate->pending_reads == NULL);
	q = xcalloc(1, sizeof(*q));
	q->buf = buf;
	q->size = size;
	q->offset = offset;
	q->callback = callback;
	q->callback_data = callback_data;
	linklistPush(&(aiostate->pending_reads), q);
	return;
    }
    sio->read.callback = callback;
    sio->read.callback_data = callback_data;
    aiostate->read_buf = buf;
    cbdataLock(callback_data);
    debug(78, 3) ("storeAufsRead: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, aiostate->fd);
    sio->offset = offset;
    aiostate->flags.reading = 1;
    aioRead(aiostate->fd, offset, buf, size, storeAufsReadDone, sio);
}


/* Write */
void
storeAufsWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    debug(78, 3) ("storeAufsWrite: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, aiostate->fd);
    if (aiostate->fd < 0) {
	/* disk file not opened yet */
	struct _queued_write *q;
	assert(aiostate->flags.opening);
	q = xcalloc(1, sizeof(*q));
	q->buf = buf;
	q->size = size;
	q->offset = offset;
	q->free_func = free_func;
	linklistPush(&(aiostate->pending_writes), q);
	return;
    }
    if (aiostate->flags.writing) {
	struct _queued_write *q;
	debug(78, 3) ("storeAufsWrite: queuing write\n");
	q = xcalloc(1, sizeof(*q));
	q->buf = buf;
	q->size = size;
	q->offset = offset;
	q->free_func = free_func;
	linklistPush(&(aiostate->pending_writes), q);
	return;
    }
    aiostate->flags.writing = 1;
    /*
     * XXX it might be nice if aioWrite() gave is immediate
     * feedback here about EWOULDBLOCK instead of in the
     * callback function
     */
    aioWrite(aiostate->fd, offset, buf, size, storeAufsWriteDone, sio,
	free_func);
}

/* Unlink */
void
storeAufsUnlink(SwapDir * SD, StoreEntry * e)
{
    debug(78, 3) ("storeAufsUnlink: dirno %d, fileno %08X\n", SD->index, e->swap_filen);
    storeAufsDirReplRemove(e);
    storeAufsDirUnlinkFile(SD, e->swap_filen);
}

/*  === STATIC =========================================================== */

static int
storeAufsKickWriteQueue(storeIOState * sio)
{
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    struct _queued_write *q = linklistShift(&aiostate->pending_writes);
    if (NULL == q)
	return 0;
    debug(78, 3) ("storeAufsKickWriteQueue: writing queued chunk of %d bytes\n",
	q->size);
    storeAufsWrite(INDEXSD(sio->swap_dirn), sio, q->buf, q->size, q->offset, q->free_func);
    xfree(q);
    return 1;
}

static int
storeAufsKickReadQueue(storeIOState * sio)
{
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    struct _queued_read *q = linklistShift(&(aiostate->pending_reads));
    if (NULL == q)
	return 0;
    debug(78, 3) ("storeAufsKickReadQueue: reading queued request of %d bytes\n",
	q->size);
    storeAufsRead(INDEXSD(sio->swap_dirn), sio, q->buf, q->size, q->offset, q->callback, q->callback_data);
    xfree(q);
    return 1;
}

static void
storeAufsOpenDone(int unused, void *my_data, int fd, int errflag)
{
    storeIOState *sio = my_data;
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    debug(78, 3) ("storeAufsOpenDone: FD %d, errflag %d\n", fd, errflag);
    Opening_FD--;
    aiostate->flags.opening = 0;
    if (errflag || fd < 0) {
	errno = errflag;
	debug(78, 0) ("storeAufsOpenDone: %s\n", xstrerror());
	debug(78, 1) ("\t%s\n", storeAufsDirFullPath(INDEXSD(sio->swap_dirn), sio->swap_filen, NULL));
	storeAufsIOCallback(sio, errflag);
	return;
    }
    aiostate->fd = fd;
    commSetCloseOnExec(fd);
    fd_open(fd, FD_FILE, storeAufsDirFullPath(INDEXSD(sio->swap_dirn), sio->swap_filen, NULL));
    if (sio->mode == O_WRONLY)
	storeAufsKickWriteQueue(sio);
    else if (sio->mode == O_RDONLY)
	storeAufsKickReadQueue(sio);
    debug(78, 3) ("storeAufsOpenDone: exiting\n");
}

static void
storeAufsReadDone(int fd, void *my_data, int len, int errflag)
{
    storeIOState *sio = my_data;
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    STRCB *callback = sio->read.callback;
    void *their_data = sio->read.callback_data;
    ssize_t rlen;
    debug(78, 3) ("storeAufsReadDone: dirno %d, fileno %08X, FD %d, len %d\n",
	sio->swap_dirn, sio->swap_filen, fd, len);
    aiostate->flags.reading = 0;
    if (errflag) {
	debug(78, 3) ("storeAufsReadDone: got failure (%d)\n", errflag);
	rlen = -1;
    } else {
	rlen = (ssize_t) len;
	sio->offset += len;
    }
    assert(callback);
    assert(their_data);
    sio->read.callback = NULL;
    sio->read.callback_data = NULL;
    if (cbdataValid(their_data))
	callback(their_data, aiostate->read_buf, rlen);
    cbdataUnlock(their_data);
    /* 
     * XXX is this safe?  The above callback may have caused sio
     * to be freed/closed already? Philip Guenther <guenther@gac.edu>
     * says it fixes his FD leaks, with no side effects.
     */
    if (aiostate->flags.close_request)
	storeAufsIOCallback(sio, DISK_OK);
}

/*
 * XXX TODO
 * if errflag == EWOULDBLOCK, then we'll need to re-queue the
 * chunk at the beginning of the write_pending list and try
 * again later.
 */
static void
storeAufsWriteDone(int fd, void *my_data, int len, int errflag)
{
    static int loop_detect = 0;
    storeIOState *sio = my_data;
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    debug(78, 3) ("storeAufsWriteDone: dirno %d, fileno %08X, FD %d, len %d\n",
	sio->swap_dirn, sio->swap_filen, fd, len);
    assert(++loop_detect < 10);
    aiostate->flags.writing = 0;
    if (errflag) {
	debug(78, 0) ("storeAufsWriteDone: got failure (%d)\n", errflag);
	storeAufsIOCallback(sio, errflag);
	loop_detect--;
	return;
    }
    sio->offset += len;
    if (storeAufsKickWriteQueue(sio))
	(void) 0;
    else if (aiostate->flags.close_request)
	storeAufsIOCallback(sio, errflag);
    loop_detect--;
}

static void
storeAufsIOCallback(storeIOState * sio, int errflag)
{
    STIOCB *callback = sio->callback;
    void *their_data = sio->callback_data;
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    int fd = aiostate->fd;
    debug(78, 3) ("storeAufsIOCallback: errflag=%d\n", errflag);
    sio->callback = NULL;
    sio->callback_data = NULL;
    debug(78, 3) ("%s:%d\n", __FILE__, __LINE__);
    if (callback)
	if (NULL == their_data || cbdataValid(their_data))
	    callback(their_data, errflag, sio);
    debug(78, 3) ("%s:%d\n", __FILE__, __LINE__);
    cbdataUnlock(their_data);
    aiostate->fd = -1;
    cbdataFree(sio);
    if (fd < 0)
	return;
    debug(78, 3) ("%s:%d\n", __FILE__, __LINE__);
    aioClose(fd);
    fd_close(fd);
    store_open_disk_fd--;
    debug(78, 3) ("%s:%d\n", __FILE__, __LINE__);
}


static int
storeAufsSomethingPending(storeIOState * sio)
{
    aiostate_t *aiostate = (aiostate_t *) sio->fsstate;
    if (aiostate->flags.reading)
	return 1;
    if (aiostate->flags.writing)
	return 1;
    if (aiostate->flags.opening)
	return 1;
    return 0;
}


/*      
 * We can't pass memFree() as a free function here, because we need to free
 * the fsstate variable ..
 */
static void
storeAufsIOFreeEntry(void *sio, int foo)
{
    memPoolFree(aio_state_pool, ((storeIOState *) sio)->fsstate);
    memFree(sio, MEM_STORE_IO);
}
