
/*
 * $Id: store_io_ufs.cc,v 1.26 2004/11/07 23:29:51 hno Exp $
 *
 * DEBUG: section 79    Storage Manager UFS Interface
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

#include "squid.h"
#include "store_ufs.h"
#include "Store.h"
#include "ufscommon.h"

#include "SwapDir.h"

UfsIO UfsIO::Instance;
bool
UfsIO::shedLoad()
{
    return false;
}

int
UfsIO::load()
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

StoreIOState::Pointer
UfsIO::createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const
{
    return new UFSStoreState (SD, e, callback, callback_data);
}

DiskFile::Pointer
UfsIO::newFile (char const *path)
{
    return new UFSFile (path);
}

void
UfsIO::unlinkFile(char const *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#elif USE_TRUNCATE

    truncate(path, 0);
#else

    ::unlink(path);
#endif
}

CBDATA_CLASS_INIT(UFSStoreState);

void *
UFSStoreState::operator new (size_t)
{
    CBDATA_INIT_TYPE(UFSStoreState);
    return cbdataAlloc(UFSStoreState);
}

void
UFSStoreState::operator delete (void *address)
{
    cbdataFree(address);
}

CBDATA_CLASS_INIT(UFSFile);
void *
UFSFile::operator new (size_t)
{
    CBDATA_INIT_TYPE(UFSFile);
    UFSFile *result = cbdataAlloc(UFSFile);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    return cbdataReference(result);
}

void
UFSFile::operator delete (void *address)
{
    UFSFile *t = static_cast<UFSFile *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}

UFSFile::UFSFile (char const *aPath) : fd (-1), closed (true), error_(false)
{
    assert (aPath);
    debug (79,3)("UFSFile::UFSFile: %s\n", aPath);
    path_ = xstrdup (aPath);
}

UFSFile::~UFSFile()
{
    safe_free (path_);
    doClose();
}

void
UFSFile::open (int flags, mode_t mode, IORequestor::Pointer callback)
{
    /* Simulate async calls */
    fd = file_open(path_ , flags);
    ioRequestor = callback;

    if (fd < 0) {
        debug(79, 1) ("UFSFile::open: Failed to open %s (%s)\n", path_, xstrerror());
        error(true);
    } else {
        closed = false;
        store_open_disk_fd++;
        debug(79, 3) ("UFSFile::open: opened FD %d\n", fd);
    }

    callback->ioCompletedNotification();
}

void
UFSFile::create (int flags, mode_t mode, IORequestor::Pointer callback)
{
    /* We use the same logic path for open */
    open(flags, mode, callback);
}


void UFSFile::doClose()
{
    if (fd > -1) {
        closed = true;
        file_close(fd);
        store_open_disk_fd--;
        fd = -1;
    }
}

void
UFSFile::close ()
{
    debug (79,3)("UFSFile::close: %p closing for %p\n", this, ioRequestor.getRaw());
    doClose();
    assert (ioRequestor.getRaw());
    ioRequestor->closeCompleted();
}

bool
UFSFile::canRead() const
{
    return fd > -1;
}

bool
UFSFile::error() const
{
    if ((fd < 0 && !closed) || error_)
        return true;

    return false;
}

void UFSFile::error(bool const &aBool)
{
    error_ = aBool;
}

void
UFSStoreState::ioCompletedNotification()
{
    if (opening) {
        opening = false;
        debug(79, 3) ("storeDiskdOpenDone: dirno %d, fileno %08x status %d\n",
                      swap_dirn, swap_filen, theFile->error());
        assert (FILE_MODE(mode) == O_RDONLY);
        openDone();

        return;
    }

    if (creating) {
        creating = false;
        debug(79, 3) ("storeDiskdCreateDone: dirno %d, fileno %08x status %d\n",
                      swap_dirn, swap_filen, theFile->error());
        openDone();

        return;
    }

    assert (!(closing ||opening));
    debug(79, 3) ("diskd::ioCompleted: dirno %d, fileno %08x status %d\n",                      swap_dirn, swap_filen, theFile->error());
    /* Ok, notification past open means an error has occured */
    assert (theFile->error());
    doCallback(DISK_ERROR);
}

void
UFSStoreState::openDone()
{
    if (theFile->error()) {
        doCallback(DISK_ERROR);
        return;
    }

    if (FILE_MODE(mode) == O_WRONLY) {
        if (kickWriteQueue())
            return;
    } else if ((FILE_MODE(mode) == O_RDONLY) && !closing) {
        if (kickReadQueue())
            return;
    }

    if (closing && !theFile->ioInProgress())
        doCallback(theFile->error() ? -1 : 0);

    debug(79, 3) ("squidaiostate_t::openDone: exiting\n");
}

void
UFSStoreState::closeCompleted()
{
    assert (closing);
    debug(79, 3) ("UFSStoreState::closeCompleted: dirno %d, fileno %08x status %d\n",
                  swap_dirn, swap_filen, theFile->error());

    if (theFile->error())
        doCallback(DISK_ERROR);
    else
        doCallback(DISK_OK);

    closing = false;
}

/* Close */
void
UFSStoreState::close()
{
    debug(79, 3) ("UFSStoreState::close: dirno %d, fileno %08X\n", swap_dirn,
                  swap_filen);
    /* mark the object to be closed on the next io that completes */
    closing = true;
    theFile->close();
}

void
UFSStoreState::read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data)
{
    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    assert(!reading);
    assert(!closing);
    assert (callback);

    if (!theFile->canRead()) {
        debug(79, 3) ("UFSStoreState::read_: queueing read because theFile can't read\n");
        queueRead (buf, size, offset, callback, callback_data);
        return;
    }

    read.callback = callback;
    read.callback_data = cbdataReference(callback_data);
    debug(79, 3) ("UFSStoreState::read_: dirno %d, fileno %08X\n",
                  swap_dirn, swap_filen);
    offset_ = offset;
    read_buf = buf;
    reading = true;
    theFile->read(buf, offset, size);
}

void
UFSFile::read(char *buf, off_t offset, size_t size)
{
    assert (fd > -1);
    assert (ioRequestor.getRaw());
    file_read(fd, buf, size, offset, ReadDone, this);
}

void
UFSFile::ReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
{
    UFSFile *myFile = static_cast<UFSFile *>(my_data);
    assert (myFile);
    myFile->readDone (fd, buf, len, errflag);
}

void
UFSFile::write(char const *buf, size_t size, off_t offset, FREE *free_func)
{
    debug(79, 3) ("storeUfsWrite: FD %d\n",fd);
    file_write(fd,
               offset,
               (char *)buf,
               size,
               WriteDone,
               this,
               free_func);
}

void
UFSStoreState::write(char const *buf, size_t size, off_t offset, FREE * free_func)
{
    debug(79, 3) ("UFSStoreState::write: dirn %d, fileno %08X\n", swap_dirn, swap_filen);

    if (!theFile->canWrite()) {
        assert(creating || writing);
        queueWrite(buf, size, offset, free_func);
        return;
    }

    writing = true;
    theFile->write(buf,size,offset,free_func);
}

bool
UFSFile::ioInProgress()const
{
    /* IO is never pending with UFS */
    return false;
}

/*  === STATIC =========================================================== */

void
UFSFile::readDone(int rvfd, const char *buf, int len, int errflag)
{
    debug (79,3)("UFSFile::readDone: FD %d\n",rvfd);
    assert (fd == rvfd);

    ssize_t rlen;

    if (errflag) {
        debug(79, 3) ("UFSFile::readDone: got failure (%d)\n", errflag);
        rlen = -1;
    } else {
        rlen = (ssize_t) len;
    }

    if (errflag == DISK_EOF)
        errflag = DISK_OK;	/* EOF is signalled by len == 0, not errors... */

    ioRequestor->readCompleted(buf, rlen, errflag);
}

void
UFSStoreState::readCompleted(const char *buf, int len, int errflag)
{
    reading = false;
    debug(79, 3) ("storeDiskdReadDone: dirno %d, fileno %08x len %d\n",
                  swap_dirn, swap_filen, len);

    if (len > 0)
        offset_ += len;

    STRCB *callback = read.callback;

    assert(callback);

    read.callback = NULL;

    void *cbdata;

    /* A note:
     * diskd IO queues closes via the diskd queue. So close callbacks
     * occur strictly after reads and writes.
     * ufs doesn't queue, it simply completes, so close callbacks occur
     * strictly after reads and writes.
     * aufs performs closes syncronously, so close events must be managed
     * to force strict ordering.
     * The below does this:
     * closing is set when close() is called, and close only triggers
     * when no io's are pending.
     * writeCompleted likewise.
     */
    if (!closing && cbdataReferenceValidDone(read.callback_data, &cbdata)) {
        if (len > 0 && read_buf != buf)
            memcpy(read_buf, buf, len);

        callback(cbdata, read_buf, len);
    } else if (closing && theFile.getRaw()!= NULL && !theFile->ioInProgress())
        doCallback(errflag);
}

void
UFSFile::WriteDone (int fd, int errflag, size_t len, void *me)
{
    UFSFile *aFile = static_cast<UFSFile *>(me);
    aFile->writeDone (fd, errflag, len);
}

void
UFSFile::writeDone(int rvfd, int errflag, size_t len)
{
    assert (rvfd == fd);
    debug(79, 3) ("storeUfsWriteDone: FD %d, len %ld\n",
                  fd, (long int) len);

    if (errflag) {
        debug(79, 0) ("storeUfsWriteDone: got failure (%d)\n", errflag);
        doClose();
        ioRequestor->writeCompleted (DISK_ERROR,0);
        return;
    }

    ioRequestor->writeCompleted(DISK_OK, len);
}

void
UFSStoreState::writeCompleted(int errflag, size_t len)
{
    debug(79, 3) ("storeUfsWriteDone: dirno %d, fileno %08X, len %ld\n",
                  swap_dirn, swap_filen, (long int) len);
    writing = false;

    offset_ += len;

    if (theFile->error()) {
        doCallback(DISK_ERROR);
        return;
    }

    if (closing && !theFile->ioInProgress()) {
        theFile->close();
        return;
    }

    if (!flags.write_kicking) {
        flags.write_kicking = true;
        /* While we start and complete syncronously io's. */

        while (kickWriteQueue() && !theFile->ioInProgress())

            ;
        flags.write_kicking = false;

        if (!theFile->ioInProgress() && closing)
            doCallback(errflag);
    }
}

void
UFSStoreState::doCallback(int errflag)
{
    debug(79, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    STIOCB *theCallback = callback;
    callback = NULL;

    void *cbdata;

    if (cbdataReferenceValidDone(callback_data, &cbdata) && theCallback)
        theCallback(cbdata, errflag, this);

    /* We are finished with the file as this is on close or error only.*/
    /* This must be the last line, as theFile may be the only object holding
     * us in memory 
     */
    theFile = NULL;
}

/* ============= THE REAL UFS CODE ================ */

UFSStoreState::UFSStoreState(SwapDir * SD, StoreEntry * anEntry, STIOCB * callback_, void *callback_data_) : opening (false), creating (false), closing (false), reading(false), writing(false), pending_reads(NULL), pending_writes (NULL)
{
    swap_filen = anEntry->swap_filen;
    swap_dirn = SD->index;
    mode = O_BINARY;
    callback = callback_;
    callback_data = cbdataReference(callback_data_);
    e = anEntry;
    flags.write_kicking = false;
}

UFSStoreState::~UFSStoreState()
{
    _queued_read *qr;

    while ((qr = (_queued_read *)linklistShift(&pending_reads))) {
        cbdataReferenceDone(qr->callback_data);
        delete qr;
    }

    _queued_write *qw;

    while ((qw = (_queued_write *)linklistShift(&pending_writes))) {
        if (qw->free_func)
            qw->free_func(const_cast<char *>(qw->buf));
        delete qw;
    }
}

bool
UFSStoreState::kickReadQueue()
{
    _queued_read *q = (_queued_read *)linklistShift(&pending_reads);

    if (NULL == q)
        return false;

    debug(79, 3) ("UFSStoreState::kickReadQueue: reading queued request of %ld bytes\n",
                  (long int) q->size);

    void *cbdata;

    if (cbdataReferenceValidDone(q->callback_data, &cbdata))
        read_(q->buf, q->size, q->offset, q->callback, cbdata);

    delete q;

    return true;
}

void
UFSStoreState::queueRead(char *buf, size_t size, off_t offset, STRCB *callback, void *callback_data)
{
    debug(79, 3) ("UFSStoreState::queueRead: queueing read\n");
    assert(opening);
    assert (pending_reads == NULL);
    _queued_read *q = new _queued_read;
    q->buf = buf;
    q->size = size;
    q->offset = offset;
    q->callback = callback;
    q->callback_data = cbdataReference(callback_data);
    linklistPush(&pending_reads, q);
}

bool
UFSStoreState::kickWriteQueue()
{
    _queued_write *q = (_queued_write *)linklistShift(&pending_writes);

    if (NULL == q)
        return false;

    debug(79, 3) ("storeAufsKickWriteQueue: writing queued chunk of %ld bytes\n",
                  (long int) q->size);

    write(const_cast<char *>(q->buf), q->size, q->offset, q->free_func);
    delete q;
    return true;
}

void
UFSStoreState::queueWrite(char const *buf, size_t size, off_t offset, FREE * free_func)
{
    debug(79, 3) ("UFSStoreState::queueWrite: queuing write\n");

    _queued_write *q;
    q = new _queued_write;
    q->buf = buf;
    q->size = size;
    q->offset = offset;
    q->free_func = free_func;
    linklistPush(&pending_writes, q);
}

StoreIOState::Pointer
UFSStrategy::open(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
                  STIOCB * callback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    debug(79, 3) ("UFSStrategy::open: fileno %08X\n", e->swap_filen);

    if (shedLoad()) {
        openFailed();
        return NULL;
    }

    /* to consider: make createstate a private UFSStrategy call */
    StoreIOState::Pointer sio = createState (SD, e, callback, callback_data);

    sio->mode |= O_RDONLY;

    UFSStoreState *state = dynamic_cast <UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(e->swap_filen, NULL);

    DiskFile::Pointer myFile = newFile (path);

    state->theFile = myFile;

    state->opening = true;

    myFile->open (sio->mode, 0644, state);

    if (myFile->error())
        return NULL;

    return sio;
}

StoreIOState::Pointer
UFSStrategy::create(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
                    STIOCB * callback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    /* Allocate a number */
    sfileno filn = ((UFSSwapDir *)SD)->mapBitAllocate();
    debug(79, 3) ("UFSStrategy::create: fileno %08X\n", filn);

    if (shedLoad()) {
        openFailed();
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return NULL;
    }

    /* Shouldn't we handle a 'bitmap full' error here? */

    StoreIOState::Pointer sio = createState (SD, e, callback, callback_data);

    sio->mode |= O_WRONLY | O_CREAT | O_TRUNC;

    sio->swap_filen = filn;

    UFSStoreState *state = dynamic_cast <UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(filn, NULL);

    DiskFile::Pointer myFile = newFile (path);

    state->theFile = myFile;

    state->creating = true;

    myFile->create (state->mode, 0644, state);

    if (myFile->error()) {
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return NULL;
    }

    /* now insert into the replacement policy */
    ((UFSSwapDir *)SD)->replacementAdd(e);

    return sio;
}

UfsIOModule &
UfsIOModule::GetInstance()
{
    if (!Instance)
        Instance = new UfsIOModule;

    return *Instance;
}

void
UfsIOModule::init()
{}

void
UfsIOModule::shutdown()
{}

UFSStrategy *
UfsIOModule::createSwapDirIOStrategy()
{
    return new InstanceToSingletonAdapter<UfsIO>(&UfsIO::Instance);
}

UfsIOModule *UfsIOModule::Instance = NULL;
