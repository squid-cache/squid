
/*
 * $Id: store_io_ufs.cc,v 1.15 2003/01/23 00:38:22 robertc Exp $
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
void
UfsIO::deleteSelf() const
{
    /* Do nothing, we use a single instance */
}

StoreIOState::Pointer
UfsIO::createState(SwapDir *SD, StoreEntry *e, STIOCB * callback, void *callback_data) const
{
    return new ufsstate_t (SD, e, callback, callback_data);
}

DiskFile::Pointer 
UfsIO::newFile (char const *path)
{
    return new UFSFile (path);
}

CBDATA_CLASS_INIT(ufsstate_t);

void *
ufsstate_t::operator new (size_t)
{
    CBDATA_INIT_TYPE(ufsstate_t);
    ufsstate_t *result = cbdataAlloc(ufsstate_t);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    return result;
}
 
void
ufsstate_t::operator delete (void *address)
{
    ufsstate_t *t = static_cast<ufsstate_t *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}
    
ufsstate_t::ufsstate_t(SwapDir * SD, StoreEntry * anEntry, STIOCB * callback_, void *callback_data_) 
{
    swap_filen = anEntry->swap_filen;
    swap_dirn = SD->index;
    mode = O_BINARY;
    callback = callback_;
    callback_data = cbdataReference(callback_data_);
    e = anEntry;
}

CBDATA_CLASS_INIT(UFSFile);
void *
UFSFile::operator new (size_t)
{
    CBDATA_INIT_TYPE(UFSFile);
    UFSFile *result = cbdataAlloc(UFSFile);
    /* Mark result as being owned - we want the refcounter to do the delete
     * call */
    cbdataReference(result);
    return result;
}
 
void
UFSFile::operator delete (void *address)
{
    UFSFile *t = static_cast<UFSFile *>(address);
    cbdataFree(address);
    /* And allow the memory to be freed */
    cbdataReferenceDone (t);
}

void
UFSFile::deleteSelf() const {delete this;}

UFSFile::UFSFile (char const *aPath) : fd (-1)
{
    assert (aPath);
    debug (79,0)("UFSFile::UFSFile: %s\n", aPath);
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
	debug(79, 3) ("UFSFile::open: got failure (%d)\n", errno);
    } else {
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
	file_close(fd);
	store_open_disk_fd--;
	fd = -1;
    }
}

void
UFSFile::close ()
{
    debug (79,0)("UFSFile::close: %p closing for %p\n", this, ioRequestor.getRaw());
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
    if (fd < 0)
	return true;
    return false;
}

void
ufsstate_t::ioCompletedNotification()
{
    if (opening) {
	opening = false;
	/* There is no 'opened' callback */
	return;
    }
    if (creating) {
	creating = false;
	return;
    }
    assert(0);
}

void
ufsstate_t::closeCompleted()
{
    doCallback(theFile->error() ? 0 : -1);
}

void
ufsstate_t::close()
{
    debug(79, 3) ("storeUfsClose: dirno %d, fileno %08X\n",
	swap_dirn, swap_filen);
    closing = true;
    if (!(reading || writing)) {
        ((UFSFile *)theFile.getRaw())->close();
    }
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
    if (!theFile->canWrite() || writing) {
	assert(creating || writing);
	queueWrite(buf, size, offset, free_func);
	return;
    }
    writing = true;
    theFile->write(buf,size,offset,free_func);
}

void
UfsSwapDir::unlink(StoreEntry & e)
{
    debug(79, 3) ("storeUfsUnlink: fileno %08X\n", e.swap_filen);
    replacementRemove(&e);
    mapBitReset(e.swap_filen);
    UFSSwapDir::unlinkFile(e.swap_filen);
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
ufsstate_t::readCompleted(const char *buf, int len, int errflag)
{

    reading = false;
    debug(79, 3) ("storeUfsReadDone: dirno %d, fileno %08X, len %d\n",
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
    if (closing)
	fatal("Sync ufs doesn't support overlapped close and read calls\n");
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
ufsstate_t::writeCompleted(int errflag, size_t len)
{
    debug(79, 3) ("storeUfsWriteDone: dirno %d, fileno %08X, len %ld\n",
	swap_dirn, swap_filen, (long int) len);
    writing = false;
    if (theFile->error())
	doCallback(DISK_ERROR);
    offset_ += len;
    if (closing)
        ((UFSFile *)theFile.getRaw())->close();
}

void
ufsstate_t::doCallback(int errflag)
{
    debug(79, 3) ("storeUfsIOCallback: errflag=%d\n", errflag);
    /* We are finished with the file */
    theFile = NULL;
    void *cbdata;
    if (cbdataReferenceValidDone(callback_data, &cbdata))
	callback(cbdata, errflag, this);
    callback = NULL;
}


/*
 * Clean up any references from the SIO before it get's released.
 */
ufsstate_t::~ufsstate_t()
{}



/* ============= THE REAL UFS CODE ================ */

UFSStoreState::UFSStoreState() : opening (false), creating (false), closing (false), reading(false), writing(false), pending_reads(NULL), pending_writes (NULL){}
UFSStoreState::~UFSStoreState()
{
    _queued_read *qr;
    while ((qr = (_queued_read *)linklistShift(&pending_reads))) {
	cbdataReferenceDone(qr->callback_data);
	delete qr;
    }

    struct _queued_write *qw;
    while ((qw = (struct _queued_write *)linklistShift(&pending_writes))) {
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

MemPool * UFSStoreState::_queued_read::Pool = NULL;

void *
UFSStoreState::_queued_read::operator new(size_t size)
{
    if (!Pool)
	Pool = memPoolCreate("AUFS Queued read data",sizeof (_queued_read));
    return memPoolAlloc (Pool);
}

void
UFSStoreState::_queued_read::operator delete (void *address)
{
    memPoolFree (Pool, address);
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

MemPool * UFSStoreState::_queued_write::Pool = NULL;

void *
UFSStoreState::_queued_write::operator new(size_t size)
{
    if (!Pool)
	Pool = memPoolCreate("AUFS Queued write data",sizeof (_queued_write));
    return memPoolAlloc (Pool);
}

void
UFSStoreState::_queued_write::operator delete (void *address)
{
    memPoolFree (Pool, address);
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
    struct _queued_write *q;
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
    assert (((UfsSwapDir *)SD)->IO == this);
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
    assert (((UfsSwapDir *)SD)->IO == this);
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
