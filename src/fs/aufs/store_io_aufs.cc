
/*
 * DEBUG 79
 */

#include "squid.h"
#include "store_asyncufs.h"
#include "Store.h"
#include "ufscommon.h"
#include "SwapDir.h"

static void storeAufsIOCallback(storeIOState * sio, int errflag);
static int storeAufsNeedCompletetion(storeIOState *);

/* === PUBLIC =========================================================== */



CBDATA_CLASS_INIT(squidaiostate_t);

void *
squidaiostate_t::operator new (size_t)
{
    CBDATA_INIT_TYPE(squidaiostate_t);
    squidaiostate_t *result = cbdataAlloc(squidaiostate_t);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    return result;
}
 
void
squidaiostate_t::operator delete (void *address)
{
    squidaiostate_t *t = static_cast<squidaiostate_t *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}
    
squidaiostate_t::squidaiostate_t(SwapDir * SD, StoreEntry * anEntry, STIOCB * callback_, void *callback_data_)
{
    swap_filen = anEntry->swap_filen;
    swap_dirn = SD->index;
    mode = O_BINARY;
    callback = callback_;
    callback_data = cbdataReference(callback_data_);
    e = anEntry;
    fd = -1;
}

AufsIO AufsIO::Instance;
bool
AufsIO::shedLoad()
{
    /*
     * we should detect some 'too many files open' condition and return
     * NULL here.
     */
#ifdef MAGIC2
    if (aioQueueSize() > MAGIC2)
	return true;
#endif
    return false;
}
void
AufsIO::deleteSelf() const
{
    /* do nothing, we use a single instance */
}

StoreIOState::Pointer
AufsIO::createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const
{
    return new squidaiostate_t (SD, e, callback, callback_data);
}

DiskFile::Pointer
AufsIO::newFile (char const *path)
{
    return new AUFSFile (path, this);
}

CBDATA_CLASS_INIT(AUFSFile);
void *
AUFSFile::operator new (size_t)
{
    CBDATA_INIT_TYPE(AUFSFile);
    AUFSFile *result = cbdataAlloc(AUFSFile);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    return result;
}
 
void
AUFSFile::operator delete (void *address)
{
    AUFSFile *t = static_cast<AUFSFile *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}

void
AUFSFile::deleteSelf() const {delete this;}

AUFSFile::AUFSFile (char const *aPath, AufsIO *anIO):fd(-1), errorOccured (false), IO(anIO) {
    assert (aPath);
    debug (79,3)("UFSFile::UFSFile: %s\n", aPath);
    path_ = xstrdup (aPath);
}

AUFSFile::~AUFSFile()
{
    safe_free (path_);
    doClose();
}

void
AUFSFile::open (int flags, mode_t mode, IORequestor::Pointer callback)
{
    statCounter.syscalls.disk.opens++;
#if !ASYNC_OPEN
    fd = file_open(path_, flags);
    if (fd < 0) {
	debug(79, 3) ("AUFSFile::open: got failure (%d)\n", errno);
	errorOccured = true;
	return;
    }
#endif
    Opening_FD++;
    ioRequestor = callback;
#if ASYNC_OPEN
    aioOpen(path_, flags, mode, AUFSFile::OpenDone, this);
#else
    openDone(fd, NULL, fd, 0);
#endif
}

void
AUFSFile::read(char *buf, off_t offset, size_t size)
{
    assert (fd > -1);
    assert (ioRequestor.getRaw());
    statCounter.syscalls.disk.reads++;
#if ASYNC_READ
    aioRead(fd, offset, size, ReadDone, this);
#else
    file_read(fd, buf, size, offset, ReadDone, this);
#endif
}

void
AUFSFile::create (int flags, mode_t mode, IORequestor::Pointer callback)
{
    statCounter.syscalls.disk.opens++;
#if !ASYNC_CREATE
    int fd = file_open(path_, flags);
    if (fd < 0) {
	debug(79, 3) ("storeAufsCreate: got failure (%d)\n", errno);
	errorOccured = true;
	return;
    }
#endif
    Opening_FD++;
    ioRequestor = callback;
#if ASYNC_CREATE
    aioOpen(path_, flags, mode, AUFSFile::OpenDone, this);
#else
    openDone (fd, NULL, fd, 0);
#endif
}

bool
AUFSFile::error() const
{
    return errorOccured;
}

void
AUFSFile::OpenDone(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno)
{
    AUFSFile *myFile = static_cast<AUFSFile *>(cbdata);
    myFile->openDone (fd, buf, aio_return, aio_errno);
}

void
AUFSFile::openDone(int unused, const char *unused2, int anFD, int errflag)
{
    debug(79, 3) ("AUFSFile::openDone: FD %d, errflag %d\n", anFD, errflag);
    Opening_FD--;

    fd = anFD;
    if (errflag || fd < 0) {
	errno = errflag;
	debug(79, 0) ("AUFSFile::openDone: %s\n", xstrerror());
	debug(79, 1) ("\t%s\n", path_);
	errorOccured = true;
    } else {
	store_open_disk_fd++;
	commSetCloseOnExec(fd);
	fd_open(fd, FD_FILE, path_);
    }
    
    debug(79, 3) ("AUFSFile::openDone: exiting\n");

    IORequestor::Pointer t = ioRequestor;
    t->ioCompletedNotification();
}

void AUFSFile::doClose()
{
    if (fd > -1) {
	statCounter.syscalls.disk.closes++;
	aioClose(fd);
	fd_close(fd);
	store_open_disk_fd--;
	fd = -1;
    }
}

/* open for reading */
StoreIOState::Pointer
storeAufsOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    UFSStrategy *IO = dynamic_cast <UFSStrategy *>(((AUFSSwapDir *)SD)->IO);
    assert (IO);
    return IO->open (SD, e, file_callback, callback, callback_data);
}

/* open for creating */
StoreIOState::Pointer
storeAufsCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    UFSStrategy *IO = dynamic_cast <UFSStrategy *>(((AUFSSwapDir *)SD)->IO);
    assert (IO);
    return IO->create (SD, e, file_callback, callback, callback_data);
}

/* Close */
void
squidaiostate_t::close()
{
    debug(79, 3) ("storeAufsClose: dirno %d, fileno %08X, FD %d\n",
	swap_dirn, swap_filen, fd);
    /* mark the object to be closed on the next io that completes */
    if (storeAufsNeedCompletetion(this)) {
	closing = true;
	return;
    }
    storeAufsIOCallback(this, DISK_OK);
}

bool
AUFSFile::canRead() const
{
    debug (79,3)("AUFSFile::canRead: fd is %d\n",fd);
    return fd > -1;
}

void
AUFSFile::write(char const *buf, size_t size, off_t offset, FREE *free_func)
{
    debug(79, 3) ("storeAufsWrite: FD %d\n", fd);
    statCounter.syscalls.disk.writes++;
#if ASYNC_WRITE
    aioWrite(fd, offset, (char *)buf, size, WriteDone, this,
	free_func);
#else
    file_write(fd, offset, (char *)buf, size, WriteDone, this,
	free_func);
#endif
}

bool
AUFSFile::canWrite() const {
    return fd > -1;
}

/* Unlink */
void
AUFSSwapDir::unlink(StoreEntry & e)
{
    debug(79, 3) ("storeAufsUnlink: dirno %d, fileno %08X\n", index, e.swap_filen);
    statCounter.syscalls.disk.unlinks++;
    replacementRemove(&e);
    mapBitReset(e.swap_filen);
    UFSSwapDir::unlinkFile(e.swap_filen);
}

/*  === STATIC =========================================================== */

#if ASYNC_READ
void
AUFSFile::ReadDone(int fd, void *my_data, const char *buf, int len, int errflag)
#else
void
AUFSFile::ReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
#endif
{
    AUFSFile *myFile = static_cast<AUFSFile *>(my_data);
    assert (myFile);
    myFile->readDone (fd, buf, len, errflag); 
}

void
AUFSFile::readDone(int rvfd, const char *buf, int len, int errflag)
{
    debug (79,3)("AUFSFile::readDone: FD %d\n",rvfd);
    assert (fd == rvfd);

    ssize_t rlen;
    if (errflag) {
	debug(79, 3) ("AUFSFile::readDone: got failure (%d)\n", errflag);
	rlen = -1;
    } else {
	rlen = (ssize_t) len;
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
    ioRequestor->readCompleted(buf, rlen, errflag);
}

void
squidaiostate_t::readCompleted(const char *buf, int len, int errflag)
{
    int localinreaddone = flags.inreaddone;	/* Protect from callback loops */
    flags.inreaddone = 1;
    reading = false;
    debug(79, 3) ("squidaiostate_t::readCompleted: dirno %d, fileno %08X, len %d\n",
	swap_dirn, swap_filen, len);
    if (len > 0)
	offset_ += len;

    STRCB *callback = read.callback;
    assert(callback);
    read.callback = NULL;
    void *cbdata;
    if (!closing && cbdataReferenceValidDone(read.callback_data, &cbdata)) {
	if (len > 0 && read_buf != buf)
	    memcpy(read_buf, buf, len);
	callback(cbdata, read_buf, len);
    }

    flags.inreaddone = 0;
    if (closing && !localinreaddone)
	storeAufsIOCallback(this, errflag);
}
  

void
squidaiostate_t::writeCompleted(int errflag, size_t len)
{
    debug(79, 3) ("storeAufsWriteDone: dirno %d, fileno %08X, len %ld, err=%d\n",
	swap_dirn, swap_filen, (long int) len, errflag);
    writing = false;
    if (errflag) {
	debug(79, 0) ("storeAufsWriteDone: got failure (%d)\n", errflag);
	storeAufsIOCallback(this, errflag);
	return;
    }
    offset_ += len;

#if ASYNC_WRITE
    if (!kickWriteQueue())
	0;
    else if (closing)
	storeAufsIOCallback(this, errflag);
#else
    if (!flags.write_kicking) {
	flags.write_kicking = 1;
	while (kickWriteQueue())
	    (void) 0;
	flags.write_kicking = 0;
	if (closing)
	    storeAufsIOCallback(this, errflag);
    }
#endif
}

void
AUFSFile::
#if ASYNC_WRITE
WriteDone(int fd, void *my_data, int len, int errflag)
#else
WriteDone(int fd, int errflag, size_t len, void *my_data)
#endif
{
    AUFSFile *aFile = static_cast<AUFSFile *>(my_data);
    assert (aFile);
    aFile->writeDone (fd, errflag, len);
}

void
AUFSFile::writeDone (int rvfd, int errflag, size_t len)
{
    assert (rvfd == fd);
    static int loop_detect = 0;
    debug(79, 3) ("storeAufsWriteDone: FD %d, len %ld, err=%d\n",
	fd, (long int) len, errflag);

#if ASYNC_WRITE
    /* Translate from errno to Squid disk error */
    errno = errflag;
    if (errflag)
	errflag = errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR;
    else
	errflag = DISK_OK;
#endif
    assert(++loop_detect < 10);

    ioRequestor->writeCompleted(errflag, len);
    --loop_detect;
}

static void
storeAufsIOCallback(storeIOState * sio, int errflag)
{
    STIOCB *callback = sio->callback;
    squidaiostate_t *aiostate = dynamic_cast<squidaiostate_t *>(sio);
    int fd = aiostate->fd;
    debug(79, 3) ("storeAufsIOCallback: errflag=%d\n", errflag);
    debug(79, 9) ("%s:%d\n", __FILE__, __LINE__);
    if (callback) {
	void *cbdata;
	sio->callback = NULL;
	if (cbdataReferenceValidDone(sio->callback_data, &cbdata))
	    callback(cbdata, errflag, sio);
    }
    debug(79, 9) ("%s:%d\n", __FILE__, __LINE__);
    aiostate->fd = -1;
    if (aiostate->opening || aiostate->creating)
	Opening_FD--;
    if (fd < 0)
	return;
    debug(79, 9) ("%s:%d\n", __FILE__, __LINE__);
    aiostate->theFile = NULL;
    debug(79, 9) ("%s:%d\n", __FILE__, __LINE__);
}


static int
storeAufsNeedCompletetion(storeIOState * sio)
{
    squidaiostate_t *aiostate = dynamic_cast<squidaiostate_t *>(sio);

    if (aiostate->writing)
	return true;
    if (aiostate->creating && FILE_MODE(sio->mode) == O_WRONLY)
	return 1;
    if (aiostate->reading)
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
squidaiostate_t::~squidaiostate_t()
{
}

void
squidaiostate_t::ioCompletedNotification()
{
    if (opening) {
	opening = false;
	openDone();
	return;
    }
    if (creating) {
	creating = false;
	openDone();
	return;
    }
    assert (0);
}

void
squidaiostate_t::closeCompleted()
{
    assert (0);
}

void 
squidaiostate_t::openDone()
{
    if (theFile->error()) {
	storeAufsIOCallback(this, DISK_ERROR);
	return;
    }
    fd = theFile->getFD();
    if (FILE_MODE(mode) == O_WRONLY) {
	if (kickWriteQueue())
	    return;
    } else if ((FILE_MODE(mode) == O_RDONLY) && !closing) {
	if (kickReadQueue())
	    return;
    }
    if (closing)
	storeAufsIOCallback(this, theFile->error() ? -1 : 0);
    debug(79, 3) ("squidaiostate_t::openDone: exiting\n");
}
