
/*
 * DEBUG 79
 */

#include "squid.h"
#include "store_asyncufs.h"
#include "Store.h"
#include "ufscommon.h"

#if ASYNC_READ
static AIOCB storeAufsReadDone;
#else
static DRCB storeAufsReadDone;
#endif
#if ASYNC_WRITE
static AIOCB storeAufsWriteDone;
#else
static DWCB storeAufsWriteDone;
#endif
static void storeAufsIOCallback(storeIOState * sio, int errflag);
static AIOCB storeAufsOpenDone;
static int storeAufsSomethingPending(storeIOState *);
static int storeAufsKickWriteQueue(storeIOState * sio);
static CBDUNL storeAufsIOFreeEntry;

CBDATA_TYPE(storeIOState);

/* === PUBLIC =========================================================== */

/* open for reading */
storeIOState *
storeAufsOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    sfileno f = e->swap_filen;
    char *path = commonUfsDirFullPath(SD, f, NULL);
    storeIOState *sio;
#if !ASYNC_OPEN
    int fd;
#endif
    debug(79, 3) ("storeAufsOpen: fileno %08X\n", f);
    /*
     * we should detect some 'too many files open' condition and return
     * NULL here.
     */
#ifdef MAGIC2
    if (aioQueueSize() > MAGIC2)
	return NULL;
#endif
#if !ASYNC_OPEN
    fd = file_open(path, O_RDONLY | O_BINARY);
    if (fd < 0) {
	debug(79, 3) ("storeAufsOpen: got failure (%d)\n", errno);
	return NULL;
    }
#endif
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeAufsIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    sio->fsstate = memPoolAlloc(squidaio_state_pool);
    ((squidaiostate_t *) (sio->fsstate))->fd = -1;
    ((squidaiostate_t *) (sio->fsstate))->flags.opening = 1;
    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->mode = O_RDONLY | O_BINARY;
    sio->callback = callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = e;
    Opening_FD++;
#if ASYNC_OPEN
    aioOpen(path, O_RDONLY | O_BINARY, 0644, storeAufsOpenDone, sio);
#else
    storeAufsOpenDone(fd, sio, fd, 0);
#endif
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
#if !ASYNC_CREATE
    int fd;
#endif

    /* Allocate a number */
    dirn = SD->index;
    filn = commonUfsDirMapBitAllocate(SD);
    path = commonUfsDirFullPath(SD, filn, NULL);

    debug(79, 3) ("storeAufsCreate: fileno %08X\n", filn);
    /*
     * we should detect some 'too many files open' condition and return
     * NULL here.
     */
#ifdef MAGIC2
    if (aioQueueSize() > MAGIC2)
	return NULL;
#endif
#if !ASYNC_CREATE
    fd = file_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY);
    if (fd < 0) {
	debug(79, 3) ("storeAufsCreate: got failure (%d)\n", errno);
	return NULL;
    }
#endif
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeAufsIOFreeEntry);
    sio = cbdataAlloc(storeIOState);
    sio->fsstate = memPoolAlloc(squidaio_state_pool);
    ((squidaiostate_t *) (sio->fsstate))->fd = -1;
    ((squidaiostate_t *) (sio->fsstate))->flags.opening = 1;
    sio->swap_filen = filn;
    sio->swap_dirn = dirn;
    sio->mode = O_WRONLY | O_BINARY;
    sio->callback = callback;
    sio->callback_data = cbdataReference(callback_data);
    sio->e = (StoreEntry *) e;
    Opening_FD++;
#if ASYNC_CREATE
    aioOpen(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644, storeAufsOpenDone, sio);
#else
    storeAufsOpenDone(fd, sio, fd, 0);
#endif

    /* now insert into the replacement policy */
    commonUfsDirReplAdd(SD, e);
    return sio;

}



/* Close */
void
storeAufsClose(SwapDir * SD, storeIOState * sio)
{
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    debug(79, 3) ("storeAufsClose: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, aiostate->fd);
    if (storeAufsSomethingPending(sio)) {
	aiostate->flags.close_request = 1;
	return;
    }
    storeAufsIOCallback(sio, DISK_OK);
}


/* Read */
void
storeAufsRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    assert(!aiostate->flags.reading);
    if (aiostate->fd < 0) {
	struct _queued_read *q;
	debug(79, 3) ("storeAufsRead: queueing read because FD < 0\n");
	assert(aiostate->flags.opening);
	assert(aiostate->pending_reads == NULL);
	q = (struct _queued_read *)memPoolAlloc(aufs_qread_pool);
	q->buf = buf;
	q->size = size;
	q->offset = offset;
	q->callback = callback;
	q->callback_data = callback_data;
	linklistPush(&(aiostate->pending_reads), q);
	return;
    }
    sio->read.callback = callback;
    sio->read.callback_data = cbdataReference(callback_data);
    aiostate->read_buf = buf;
    debug(79, 3) ("storeAufsRead: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, aiostate->fd);
    sio->offset = offset;
    aiostate->flags.reading = 1;
#if ASYNC_READ
    aioRead(aiostate->fd, offset, buf, size, storeAufsReadDone, sio);
#else
    file_read(aiostate->fd, buf, size, offset, storeAufsReadDone, sio);
#endif
}


/* Write */
void
storeAufsWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, off_t offset, FREE * free_func)
{
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    debug(79, 3) ("storeAufsWrite: dirno %d, fileno %08X, FD %d\n",
	sio->swap_dirn, sio->swap_filen, aiostate->fd);
    if (aiostate->fd < 0) {
	/* disk file not opened yet */
	struct _queued_write *q;
	assert(aiostate->flags.opening);
	q = (struct _queued_write *)memPoolAlloc(aufs_qwrite_pool);
	q->buf = buf;
	q->size = size;
	q->offset = offset;
	q->free_func = free_func;
	linklistPush(&(aiostate->pending_writes), q);
	return;
    }
#if ASYNC_WRITE
    if (aiostate->flags.writing) {
	struct _queued_write *q;
	debug(79, 3) ("storeAufsWrite: queuing write\n");
	q = (struct _queued_write *)memPoolAlloc(aufs_qwrite_pool);
	q->buf = buf;
	q->size = size;
	q->offset = offset;
	q->free_func = free_func;
	linklistPush(&(aiostate->pending_writes), q);
	return;
    }
    aiostate->flags.writing = 1;
    aioWrite(aiostate->fd, offset, buf, size, storeAufsWriteDone, sio,
	free_func);
#else
    file_write(aiostate->fd, offset, buf, size, storeAufsWriteDone, sio,
	free_func);
#endif
}

/* Unlink */
void
storeAufsUnlink(SwapDir * SD, StoreEntry * e)
{
    debug(79, 3) ("storeAufsUnlink: dirno %d, fileno %08X\n", SD->index, e->swap_filen);
    commonUfsDirReplRemove(e);
    commonUfsDirMapBitReset(SD, e->swap_filen);
    commonUfsDirUnlinkFile(SD, e->swap_filen);
}

/*  === STATIC =========================================================== */

static int
storeAufsKickWriteQueue(storeIOState * sio)
{
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    struct _queued_write *q = (struct _queued_write *)linklistShift(&aiostate->pending_writes);
    if (NULL == q)
	return 0;
    debug(79, 3) ("storeAufsKickWriteQueue: writing queued chunk of %ld bytes\n",
	(long int) q->size);
    storeAufsWrite(INDEXSD(sio->swap_dirn), sio, q->buf, q->size, q->offset, q->free_func);
    memPoolFree(aufs_qwrite_pool, q);
    return 1;
}

static int
storeAufsKickReadQueue(storeIOState * sio)
{
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    struct _queued_read *q = (struct _queued_read *)linklistShift(&(aiostate->pending_reads));
    if (NULL == q)
	return 0;
    debug(79, 3) ("storeAufsKickReadQueue: reading queued request of %ld bytes\n",
	(long int) q->size);
    storeAufsRead(INDEXSD(sio->swap_dirn), sio, q->buf, q->size, q->offset, q->callback, q->callback_data);
    memPoolFree(aufs_qread_pool, q);
    return 1;
}

static void
storeAufsOpenDone(int unused, void *my_data, int fd, int errflag)
{
    storeIOState *sio = (storeIOState *)my_data;
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    debug(79, 3) ("storeAufsOpenDone: FD %d, errflag %d\n", fd, errflag);
    Opening_FD--;
    aiostate->flags.opening = 0;
    if (errflag || fd < 0) {
	errno = errflag;
	debug(79, 0) ("storeAufsOpenDone: %s\n", xstrerror());
	debug(79, 1) ("\t%s\n", commonUfsDirFullPath(INDEXSD(sio->swap_dirn), sio->swap_filen, NULL));
	storeAufsIOCallback(sio, DISK_ERROR);
	return;
    }
    store_open_disk_fd++;
    aiostate->fd = fd;
    commSetCloseOnExec(fd);
    fd_open(fd, FD_FILE, commonUfsDirFullPath(INDEXSD(sio->swap_dirn), sio->swap_filen, NULL));
    if (FILE_MODE(sio->mode) == O_WRONLY) {
	if (storeAufsKickWriteQueue(sio))
	    return;
    } else if (FILE_MODE(sio->mode) == O_RDONLY) {
	if (storeAufsKickReadQueue(sio))
	    return;
    }
    if (aiostate->flags.close_request)
	storeAufsIOCallback(sio, errflag);
    debug(79, 3) ("storeAufsOpenDone: exiting\n");
}

#if ASYNC_READ
static void
storeAufsReadDone(int fd, void *my_data, int len, int errflag)
#else
static void
storeAufsReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
#endif
{
    storeIOState *sio = (storeIOState *)my_data;
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    STRCB *callback = sio->read.callback;
    void *cbdata;
    ssize_t rlen;
    debug(79, 3) ("storeAufsReadDone: dirno %d, fileno %08X, FD %d, len %d\n",
	sio->swap_dirn, sio->swap_filen, fd, len);
    aiostate->flags.inreaddone = 1;
    aiostate->flags.reading = 0;
    if (errflag) {
	debug(79, 3) ("storeAufsReadDone: got failure (%d)\n", errflag);
	rlen = -1;
    } else {
	rlen = (ssize_t) len;
	sio->offset += len;
    }
#if ASYNC_READ
    /* translate errflag from errno to Squid disk error */
    errno = errflag;
    if (errflag)
	errflag = DISK_ERROR;
    else
	errflag = DISK_OK;
#else
    if (errflag == DISK_EOF)
	errflag = DISK_OK;	/* EOF is signalled by len == 0, not errors... */
#endif
    assert(callback);
    sio->read.callback = NULL;
    if (cbdataReferenceValidDone(sio->read.callback_data, &cbdata))
	callback(cbdata, aiostate->read_buf, rlen);
    aiostate->flags.inreaddone = 0;
    if (aiostate->flags.close_request)
	storeAufsIOCallback(sio, errflag);
}

#if ASYNC_WRITE
static void
storeAufsWriteDone(int fd, void *my_data, int len, int errflag)
#else
static void
storeAufsWriteDone(int fd, int errflag, size_t len, void *my_data)
#endif
{
    static int loop_detect = 0;
    storeIOState *sio = (storeIOState *)my_data;
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    debug(79, 3) ("storeAufsWriteDone: dirno %d, fileno %08X, FD %d, len %ld, err=%d\n",
	sio->swap_dirn, sio->swap_filen, fd, (long int) len, errflag);
#if ASYNC_WRITE
    /* Translate from errno to Squid disk error */
    errno = errflag;
    if (errflag)
	errflag = errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR;
    else
	errflag = DISK_OK;
#endif
    assert(++loop_detect < 10);
    aiostate->flags.writing = 0;
    if (errflag) {
	debug(79, 0) ("storeAufsWriteDone: got failure (%d)\n", errflag);
	storeAufsIOCallback(sio, errflag);
	loop_detect--;
	return;
    }
    sio->offset += len;
#if ASYNC_WRITE
    if (!storeAufsKickWriteQueue(sio))
	0;
    else if (aiostate->flags.close_request)
	storeAufsIOCallback(sio, errflag);
#else
    if (!aiostate->flags.write_kicking) {
	aiostate->flags.write_kicking = 1;
	while (storeAufsKickWriteQueue(sio))
	    (void) 0;
	aiostate->flags.write_kicking = 0;
	if (aiostate->flags.close_request)
	    storeAufsIOCallback(sio, errflag);
    }
#endif
    loop_detect--;
}

static void
storeAufsIOCallback(storeIOState * sio, int errflag)
{
    STIOCB *callback = sio->callback;
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    int fd = aiostate->fd;
    debug(79, 3) ("storeAufsIOCallback: errflag=%d\n", errflag);
    debug(79, 3) ("%s:%d\n", __FILE__, __LINE__);
    if (callback) {
	void *cbdata;
	sio->callback = NULL;
	if (cbdataReferenceValidDone(sio->callback_data, &cbdata))
	    callback(cbdata, errflag, sio);
    }
    debug(79, 3) ("%s:%d\n", __FILE__, __LINE__);
    aiostate->fd = -1;
    cbdataFree(sio);
    if (fd < 0)
	return;
    debug(79, 3) ("%s:%d\n", __FILE__, __LINE__);
    aioClose(fd);
    fd_close(fd);
    store_open_disk_fd--;
    debug(79, 3) ("%s:%d\n", __FILE__, __LINE__);
}


static int
storeAufsSomethingPending(storeIOState * sio)
{
    squidaiostate_t *aiostate = (squidaiostate_t *) sio->fsstate;
    if (aiostate->flags.reading)
	return 1;
    if (aiostate->flags.writing)
	return 1;
    if (aiostate->flags.opening)
	return 1;
    if (aiostate->flags.inreaddone)
	return 1;
    return 0;
}


/*      
 * Clean up references from the SIO before it gets released.
 * The actuall SIO is managed by cbdata so we do not need
 * to bother with that.
 */
static void
storeAufsIOFreeEntry(void *sio)
{
    memPoolFree(squidaio_state_pool, ((storeIOState *) sio)->fsstate);
}
