
/*
 * DEBUG 79
 */

#include "squid.h"
#include "store_asyncufs.h"
#include "Store.h"
#include "ufscommon.h"
#include "SwapDir.h"

/* === PUBLIC =========================================================== */




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

int
AufsIO::load()
{
    int loadav;
    int ql;

    ql = aioQueueSize();

    if (ql == 0)
        loadav = 0;

    loadav = ql * 1000 / MAGIC1;

    debug(47, 9) ("storeAufsDirCheckObj: load=%d\n", loadav);

    return loadav;
}

StoreIOState::Pointer
AufsIO::createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const
{
    return new UFSStoreState (SD, e, callback, callback_data);
}

DiskFile::Pointer
AufsIO::newFile (char const *path)
{
    return new AUFSFile (path, this);
}

void
AufsIO::unlinkFile(char const *path)
{
    statCounter.syscalls.disk.unlinks++;
#if USE_TRUNCATE_NOT_UNLINK

    aioTruncate(path, NULL, NULL);
#else

    aioUnlink(path, NULL, NULL);
#endif
}

AufsIOModule *AufsIOModule::Instance = NULL;
AufsIOModule &
AufsIOModule::GetInstance()
{
    if (!Instance)
        Instance = new AufsIOModule;

    return *Instance;
}

void
AufsIOModule::init()
{
    AufsIO::Instance.init();
}

void
AufsIOModule::shutdown()
{
    AufsIO::Instance.done();
}

UFSStrategy *
AufsIOModule::createSwapDirIOStrategy()
{
    return new InstanceToSingletonAdapter<AufsIO>(&AufsIO::Instance);
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

AUFSFile::AUFSFile (char const *aPath, AufsIO *anIO):fd(-1), errorOccured (false), IO(anIO),
        inProgressIOs (0)
{
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

    ++inProgressIOs;

#if ASYNC_OPEN

    aioOpen(path_, flags, mode, AUFSFile::OpenDone, this);

#else

    openDone(fd, NULL, fd, 0);

#endif
}

void
AUFSFile::read(char *buf, off_t offset, size_t size)
{
    debugs(79, 3, "AUFSFile::read: " << this << ", size " << size);
    assert (fd > -1);
    assert (ioRequestor.getRaw());
    statCounter.syscalls.disk.reads++;
    ++inProgressIOs;
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

    ++inProgressIOs;

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
    --inProgressIOs;
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
    UFSStrategy *IO = dynamic_cast <UFSStrategy *>(((UFSSwapDir *)SD)->IO);
    assert (IO);
    return IO->open (SD, e, file_callback, callback, callback_data);
}

/* open for creating */
StoreIOState::Pointer
storeAufsCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    UFSStrategy *IO = dynamic_cast <UFSStrategy *>(((UFSSwapDir *)SD)->IO);
    assert (IO);
    return IO->create (SD, e, file_callback, callback, callback_data);
}


void
AUFSFile::close ()
{
    debug (79,3)("AUFSFile::close: %p closing for %p\n", this, ioRequestor.getRaw());

    if (!ioInProgress()) {
        doClose();
        assert (ioRequestor.getRaw());
        ioRequestor->closeCompleted();
    }
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
    ++inProgressIOs;
#if ASYNC_WRITE

    aioWrite(fd, offset, (char *)buf, size, WriteDone, this,
             free_func);
#else

    file_write(fd, offset, (char *)buf, size, WriteDone, this,
               free_func);
#endif
}

bool
AUFSFile::canWrite() const
{
    return fd > -1;
}

bool
AUFSFile::ioInProgress()const
{
    return inProgressIOs > 0;
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

    --inProgressIOs;

    ioRequestor->readCompleted(buf, rlen, errflag);
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

    --inProgressIOs;

    ioRequestor->writeCompleted(errflag, len);

    --loop_detect;
}

