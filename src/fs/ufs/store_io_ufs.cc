
/*
 * $Id: store_io_ufs.cc,v 1.39 2007/07/24 16:15:32 rousskov Exp $
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
#include "Store.h"
#include "ufscommon.h"
#include "Generic.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"

#include "SwapDir.h"

bool
UFSStrategy::shedLoad()
{
    return io->shedLoad();
}

int
UFSStrategy::load()
{
    return io->load();
}

UFSStrategy::UFSStrategy (DiskIOStrategy *anIO) : io(anIO)
{}

UFSStrategy::~UFSStrategy ()
{
    delete io;
}

StoreIOState::Pointer
UFSStrategy::createState(SwapDir *SD, StoreEntry *e, StoreIOState::STIOCB * callback, void *callback_data) const
{
    return new UFSStoreState (SD, e, callback, callback_data);
}

DiskFile::Pointer
UFSStrategy::newFile (char const *path)
{
    return io->newFile(path);
}


void
UFSStrategy::unlinkFile(char const *path)
{
    io->unlinkFile(path);
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

void
UFSStoreState::ioCompletedNotification()
{
    if (opening) {
        opening = false;
        debugs(79, 3, "UFSStoreState::ioCompletedNotification: dirno " <<
               swap_dirn  << ", fileno "<< std::setfill('0') << std::hex <<
               std::setw(8) << swap_filen  << " status "<< std::setfill(' ') <<
               std::dec << theFile->error());

        assert (FILE_MODE(mode) == O_RDONLY);
        openDone();

        return;
    }

    if (creating) {
        creating = false;
        debugs(79, 3, "UFSStoreState::ioCompletedNotification: dirno " <<
               swap_dirn  << ", fileno "<< std::setfill('0') << std::hex <<
               std::setw(8) << swap_filen  << " status "<< std::setfill(' ') <<
               std::dec << theFile->error());

        openDone();

        return;
    }

    assert (!(closing ||opening));
    debugs(79, 3, "diskd::ioCompleted: dirno " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::setw(8) << swap_filen  <<
           " status "<< std::setfill(' ') << std::dec << theFile->error());

    /* Ok, notification past open means an error has occured */
    assert (theFile->error());
    tryClosing();
}

void
UFSStoreState::openDone()
{
    if (closing)
        debugs(0,0,HERE << "already closing in openDone()!?");

    if (theFile->error()) {
        tryClosing();
        return;
    }

    if (FILE_MODE(mode) == O_WRONLY) {
        drainWriteQueue();

    } else if ((FILE_MODE(mode) == O_RDONLY) && !closing) {
        if (kickReadQueue())
            return;
    }

    if (flags.try_closing)
        tryClosing();

    debugs(79, 3, "UFSStoreState::openDone: exiting");
}

void
UFSStoreState::closeCompleted()
{
    assert (closing);
    debugs(79, 3, "UFSStoreState::closeCompleted: dirno " << swap_dirn  <<
           ", fileno "<< std::setfill('0') << std::hex << std::setw(8) <<
           swap_filen  << " status "<< std::setfill(' ') << std::dec <<
           theFile->error());

    if (theFile->error()) {
        debugs(79,3,HERE<< "theFile->error() ret " << theFile->error());
        doCloseCallback(DISK_ERROR);
    } else {
        doCloseCallback(DISK_OK);
    }

    closing = false;
}

/*
 * DPW 2006-05-24
 * This close function is called by the higher layer when it has finished
 * reading/writing everything, or otherwise wants to close the swap
 * file.  In the case of writing and using aufs storage, close() might
 * be called before any/all data is written, and even before the open
 * callback occurs.  Thus, we use our tryClosing() method, which knows
 * when it is safe to actually signal the lower layer for closing.
 */
void
UFSStoreState::close()
{
    debugs(79, 3, "UFSStoreState::close: dirno " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen);
    tryClosing();
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
        debugs(79, 3, "UFSStoreState::read_: queueing read because theFile can't read");
        queueRead (buf, size, offset, callback, callback_data);
        return;
    }

    read.callback = callback;
    read.callback_data = cbdataReference(callback_data);
    debugs(79, 3, "UFSStoreState::read_: dirno " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen);
    offset_ = offset;
    read_buf = buf;
    reading = true;
    theFile->read(new ReadRequest(buf,offset,size));
}


/*
 * DPW 2006-05-24
 * This, the public write interface, places the write request at the end
 * of the pending_writes queue to ensure correct ordering of writes.
 * We could optimize things a little if there are no other pending
 * writes and just do the write directly.  But for now we'll keep the
 * code simpler and always go through the pending_writes queue.
 */
void
UFSStoreState::write(char const *buf, size_t size, off_t offset, FREE * free_func)
{
    debugs(79, 3, "UFSStoreState::write: dirn " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen);

    if (theFile->error()) {
        debugs(79,1,HERE << "avoid write on theFile with error");
        debugs(79,1,HERE << "calling free_func for " << (void*) buf);
        free_func((void*)buf);
        return;
    }

    queueWrite(buf, size, offset, free_func);
    drainWriteQueue();
}


/*
 * DPW 2006-05-24
 * This, the private write method, calls the lower level write for the
 * first write request in the pending_writes queue.  doWrite() is only
 * called by drainWriteQueue().
 */
void
UFSStoreState::doWrite()
{
    debugs(79, 3, HERE << this << " UFSStoreState::doWrite");

    assert(theFile->canWrite());

    _queued_write *q = (_queued_write *)linklistShift(&pending_writes);

    if (q == NULL) {
        debugs(79, 3, HERE << this << " UFSStoreState::doWrite queue is empty");
        return;
    }

    if (theFile->error()) {
        debugs(79,1,HERE << "avoid write on theFile with error");
        debugs(79,3,HERE << "calling free_func for " << (void*) q->buf);
        /*
         * DPW 2006-05-24
         * Note "free_func" is memNodeWriteComplete(), which doesn't
         * really free the memory.  Instead it clears the node's
         * write_pending flag.
         */
        q->free_func((void*)q->buf);
        delete q;
        return;
    }

    /*
     * DPW 2006-05-24
     * UFSStoreState has a 'writing' flag that we used to set here,
     * but it wasn't really used anywhere.  In fact, some lower
     * layers such as DISKD allow multiple outstanding writes, which
     * makes the boolean writing flag meaningless.  We would need
     * a counter to keep track of writes going out and write callbacks
     * coming in.  For now let's just not use the writing flag at
     * all.
     */
    debugs(79, 3, HERE << this << " calling theFile->write(" << q->size << ")");

    theFile->write(new WriteRequest(q->buf, q->offset, q->size, q->free_func));
    delete q;
}

void
UFSStoreState::readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest> result)
{
    assert (result.getRaw());
    reading = false;
    debugs(79, 3, "UFSStoreState::readCompleted: dirno " << swap_dirn  <<
           ", fileno "<< std::setfill('0') << std::hex << std::setw(8) <<
           swap_filen  << " len "<< std::setfill(' ') << std::dec << len);

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
     * closing is set when theFile->close() has been called, and close only triggers
     * when no io's are pending.
     * writeCompleted likewise.
     */
    if (!closing && cbdataReferenceValidDone(read.callback_data, &cbdata)) {
        if (len > 0 && read_buf != buf)
            memcpy(read_buf, buf, len);

        callback(cbdata, read_buf, len, this);
    }

    if (theFile != NULL && theFile->error())
        tryClosing();
}

void
UFSStoreState::writeCompleted(int errflag, size_t len, RefCount<WriteRequest> writeRequest)
{
     debugs(79, 3, "UFSStoreState::writeCompleted: dirno " << swap_dirn << ", fileno " << 
            std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen << 
            ", len " << len );
    /*
     * DPW 2006-05-24
     * See doWrites() for why we don't update UFSStoreState::writing
     * here anymore.
     */

    offset_ += len;

    if (theFile->error()) {
        debugs(79,2,HERE << "UFSStoreState::writeCompleted" <<
               " detected an error, will try to close");
        tryClosing();
    }

    /*
     * DPW 2007-04-12
     * I'm seeing disk files remain open under vanilla UFS storage
     * because storeClose() gets called before the last write is
     * complete.  I guess we have to check for the try_closing
     * flag here.
     */
    if (flags.try_closing) {
	debugs(72, 2, HERE << "UFSStoreState::writeCompleted" <<
	    " flags.try_closing is set");
	tryClosing();
    }
}

void
UFSStoreState::doCloseCallback(int errflag)
{
    debugs(79, 3, "storeUfsIOCallback: errflag=" << errflag);
    /*
     * DPW 2006-05-24
     * When we signal the higher layer with this callback, it might unlock
     * the StoreEntry and its associated data.  We must "free" any queued
     * I/Os (especially writes) now, otherwise the StoreEntry's mem_node's
     * will have their write_pending flag set, and we'll get an assertion.
     */
    freePending();
    STIOCB *theCallback = callback;
    callback = NULL;

    void *cbdata;

    if (cbdataReferenceValidDone(callback_data, &cbdata) && theCallback)
        theCallback(cbdata, errflag, this);

    /*
     * We are finished with theFile since the lower layer signalled
     * us that the file has been closed.  This must be the last line,
     * as theFile may be the only object holding us in memory.
     */
    theFile = NULL;	// refcounted
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
    flags.write_draining = false;
    flags.try_closing = false;
}

UFSStoreState::~UFSStoreState()
{
    assert(pending_reads == NULL);
    assert(pending_writes == NULL);
}

void
UFSStoreState::freePending()
{
    _queued_read *qr;

    while ((qr = (_queued_read *)linklistShift(&pending_reads))) {
        cbdataReferenceDone(qr->callback_data);
        delete qr;
    }

    debugs(79,3,HERE << "UFSStoreState::freePending: freed pending reads");

    _queued_write *qw;

    while ((qw = (_queued_write *)linklistShift(&pending_writes))) {
        if (qw->free_func)
            qw->free_func(const_cast<char *>(qw->buf));
        delete qw;
    }

    debugs(79,3,HERE << "UFSStoreState::freePending: freed pending writes");
}

bool
UFSStoreState::kickReadQueue()
{
    _queued_read *q = (_queued_read *)linklistShift(&pending_reads);

    if (NULL == q)
        return false;

    debugs(79, 3, "UFSStoreState::kickReadQueue: reading queued request of " << q->size << " bytes");

    void *cbdata;

    if (cbdataReferenceValidDone(q->callback_data, &cbdata))
        read_(q->buf, q->size, q->offset, q->callback, cbdata);

    delete q;

    return true;
}

void
UFSStoreState::queueRead(char *buf, size_t size, off_t offset, STRCB *callback, void *callback_data)
{
    debugs(79, 3, "UFSStoreState::queueRead: queueing read");
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

/*
 * DPW 2006-05-24
 * drainWriteQueue() is a loop around doWrite().
 */
void
UFSStoreState::drainWriteQueue()
{
    /*
     * DPW 2007-04-12
     * We might find that flags.write_draining is already set
     * because schemes like diskd can process I/O acks
     * before sending another I/O request.    e.g. the following
     * sequence of events: open request -> write request ->
     * drainWriteQueue() -> queue full -> callbacks -> openDone() ->
     * drainWriteQueue().
     */
    if (flags.write_draining)
	return;

    if (!theFile->canWrite())
        return;

    flags.write_draining = true;

    while (pending_writes != NULL) {
        doWrite();
    }

    flags.write_draining = false;

    if (flags.try_closing)
        tryClosing();
}

/*
 * DPW 2006-05-24
 * This blows.	DiskThreadsDiskFile::close() won't actually do the close
 * if ioInProgress() is true.  So we have to check it here.  Maybe someday
 * DiskThreadsDiskFile::close() will be modified to have a return value,
 * or will remember to do the close for us.
 */
void
UFSStoreState::tryClosing()
{
    debugs(79,3,HERE << this << " tryClosing()" <<
           " closing = " << closing <<
           " flags.try_closing = " << flags.try_closing <<
           " ioInProgress = " << theFile->ioInProgress());

    if (theFile->ioInProgress()) {
	debugs(79, 3, HERE << this <<
	    " won't close since ioInProgress is true, bailing");
        flags.try_closing = true;
        return;
    }

    closing = true;
    flags.try_closing = false;
    theFile->close();
}

void
UFSStoreState::queueWrite(char const *buf, size_t size, off_t offset, FREE * free_func)
{
    debugs(79, 3, HERE << this << " UFSStoreState::queueWrite: queueing write of size " << size);

    _queued_write *q;
    q = new _queued_write;
    q->buf = buf;
    q->size = size;
    q->offset = offset;
    q->free_func = free_func;
    linklistPush(&pending_writes, q);
}

StoreIOState::Pointer
UFSStrategy::open(SwapDir * SD, StoreEntry * e, StoreIOState::STFNCB * file_callback,
                  StoreIOState::STIOCB * callback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    debugs(79, 3, "UFSStrategy::open: fileno "<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << e->swap_filen);

    /* to consider: make createstate a private UFSStrategy call */
    StoreIOState::Pointer sio = createState (SD, e, callback, callback_data);

    sio->mode |= O_RDONLY;

    UFSStoreState *state = dynamic_cast <UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(e->swap_filen, NULL);

    DiskFile::Pointer myFile = newFile (path);

    if (myFile.getRaw() == NULL)
        return NULL;

    state->theFile = myFile;

    state->opening = true;

    myFile->open (sio->mode, 0644, state);

    if (myFile->error())
        return NULL;

    return sio;
}

StoreIOState::Pointer
UFSStrategy::create(SwapDir * SD, StoreEntry * e, StoreIOState::STFNCB * file_callback,
                    StoreIOState::STIOCB * callback, void *callback_data)
{
    assert (((UFSSwapDir *)SD)->IO == this);
    /* Allocate a number */
    sfileno filn = ((UFSSwapDir *)SD)->mapBitAllocate();
    debugs(79, 3, "UFSStrategy::create: fileno "<< std::setfill('0') << std::hex << std::uppercase << std::setw(8) << filn);

    /* Shouldn't we handle a 'bitmap full' error here? */

    StoreIOState::Pointer sio = createState (SD, e, callback, callback_data);

    sio->mode |= O_WRONLY | O_CREAT | O_TRUNC;

    sio->swap_filen = filn;

    UFSStoreState *state = dynamic_cast <UFSStoreState *>(sio.getRaw());

    assert (state);

    char *path = ((UFSSwapDir *)SD)->fullPath(filn, NULL);

    DiskFile::Pointer myFile = newFile (path);

    if (myFile.getRaw() == NULL) {
        ((UFSSwapDir *)SD)->mapBitReset (filn);
        return NULL;
    }

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

int
UFSStrategy::callback()
{
    return io->callback();
}

void
UFSStrategy::init()
{
    io->init();
}

void
UFSStrategy::sync()
{
    io->sync();
}

void
UFSStrategy::statfs(StoreEntry & sentry)const
{
    io->statfs(sentry);
}

