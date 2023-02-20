/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Storage Manager UFS Interface */

#include "squid.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "Generic.h"
#include "SquidConfig.h"
#include "Store.h"
#include "store/Disk.h"
#include "UFSStoreState.h"
#include "UFSStrategy.h"

CBDATA_NAMESPACED_CLASS_INIT(Fs::Ufs,UFSStoreState);

void
Fs::Ufs::UFSStoreState::ioCompletedNotification()
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

    /* Ok, notification past open means an error has occurred */
    assert (theFile->error());
    tryClosing();
}

void
Fs::Ufs::UFSStoreState::openDone()
{
    if (closing)
        debugs(0, DBG_CRITICAL, "already closing in openDone()!?");

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
Fs::Ufs::UFSStoreState::closeCompleted()
{
    assert (closing);
    debugs(79, 3, "UFSStoreState::closeCompleted: dirno " << swap_dirn  <<
           ", fileno "<< std::setfill('0') << std::hex << std::setw(8) <<
           swap_filen  << " status "<< std::setfill(' ') << std::dec <<
           theFile->error());

    if (theFile->error()) {
        debugs(79,3, "theFile->error() ret " << theFile->error());
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
Fs::Ufs::UFSStoreState::close(int)
{
    debugs(79, 3, "UFSStoreState::close: dirno " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen);
    tryClosing(); // UFS does not distinguish different closure types
}

void
Fs::Ufs::UFSStoreState::read_(char *buf, size_t size, off_t aOffset, STRCB * aCallback, void *aCallbackData)
{
    assert(read.callback == nullptr);
    assert(read.callback_data == nullptr);
    assert(!reading);
    assert(!closing);
    assert (aCallback);

    if (!theFile->canRead()) {
        debugs(79, 3, "queueing read because theFile can't read");
        assert(opening);
        pending_reads.emplace(buf, size, aOffset, aCallback, aCallbackData);
        return;
    }

    read.callback = aCallback;
    read.callback_data = cbdataReference(aCallbackData);
    debugs(79, 3, "UFSStoreState::read_: dirno " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen);
    offset_ = aOffset;
    read_buf = buf;
    reading = true;
    theFile->read(new ReadRequest(buf,aOffset,size));
}

/*
 * DPW 2006-05-24
 * This, the public write interface, places the write request at the end
 * of the pending_writes queue to ensure correct ordering of writes.
 * We could optimize things a little if there are no other pending
 * writes and just do the write directly.  But for now we'll keep the
 * code simpler and always go through the pending_writes queue.
 */
bool
Fs::Ufs::UFSStoreState::write(char const *buf, size_t size, off_t aOffset, FREE * free_func)
{
    debugs(79, 3, "UFSStoreState::write: dirn " << swap_dirn  << ", fileno "<<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen);

    if (theFile->error()) {
        debugs(79, DBG_IMPORTANT, "ERROR: avoid write on theFile with error");
        debugs(79, DBG_IMPORTANT, "calling free_func for " << (void*) buf);
        free_func((void*)buf);
        return false;
    }

    const Store::Disk &dir = *INDEXSD(swap_dirn);
    if (static_cast<uint64_t>(offset_ + size) > static_cast<uint64_t>(dir.maxObjectSize())) {
        debugs(79, 2, "accepted unknown-size entry grew too big: " <<
               (offset_ + size) << " > " << dir.maxObjectSize());
        free_func((void*)buf);
        tryClosing();
        return false;
    }

    debugs(79, 3, (void*)this << " queueing write of size " << size);
    pending_writes.emplace(buf, size, aOffset, free_func);
    drainWriteQueue();
    return true;
}

/*
 * DPW 2006-05-24
 * This, the private write method, calls the lower level write for the
 * first write request in the pending_writes queue.  doWrite() is only
 * called by drainWriteQueue().
 */
void
Fs::Ufs::UFSStoreState::doWrite()
{
    debugs(79, 3, (void*)this);

    assert(theFile->canWrite());

    if (pending_writes.empty()) {
        debugs(79, 3, (void*)this << " write queue is empty");
        return;
    }

    auto &q = pending_writes.front();

    if (theFile->error()) {
        debugs(79, DBG_IMPORTANT, "ERROR: " << MYNAME << "avoid write on theFile with error");
        pending_writes.pop();
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
    debugs(79, 3, (void*)this << " calling theFile->write(" << q.size << ")");

    theFile->write(new WriteRequest(q.buf, q.offset, q.size, q.free_func));
    q.buf = nullptr; // prevent buf deletion on pop, its used by the above object
    pending_writes.pop();
}

void
Fs::Ufs::UFSStoreState::readCompleted(const char *buf, int len, int, RefCount<ReadRequest> result)
{
    assert (result.getRaw());
    reading = false;
    debugs(79, 3, "UFSStoreState::readCompleted: dirno " << swap_dirn  <<
           ", fileno "<< std::setfill('0') << std::hex << std::setw(8) <<
           swap_filen  << " len "<< std::setfill(' ') << std::dec << len);

    if (len > 0)
        offset_ += len;

    STRCB *callback_ = read.callback;

    assert(callback_);

    read.callback = nullptr;

    void *cbdata;

    /* A note:
     * diskd IO queues closes via the diskd queue. So close callbacks
     * occur strictly after reads and writes.
     * ufs doesn't queue, it simply completes, so close callbacks occur
     * strictly after reads and writes.
     * aufs performs closes synchronously, so close events must be managed
     * to force strict ordering.
     * The below does this:
     * closing is set when theFile->close() has been called, and close only triggers
     * when no io's are pending.
     * writeCompleted likewise.
     */
    if (!closing && cbdataReferenceValidDone(read.callback_data, &cbdata)) {
        if (len > 0 && read_buf != buf)
            memcpy(read_buf, buf, len);

        callback_(cbdata, read_buf, len, this);
    }

    if (flags.try_closing || (theFile != nullptr && theFile->error()) )
        tryClosing();
}

void
Fs::Ufs::UFSStoreState::writeCompleted(int, size_t len, RefCount<WriteRequest>)
{
    debugs(79, 3, "dirno " << swap_dirn << ", fileno " <<
           std::setfill('0') << std::hex << std::uppercase << std::setw(8) << swap_filen <<
           ", len " << len);
    /*
     * DPW 2006-05-24
     * See doWrites() for why we don't update UFSStoreState::writing
     * here anymore.
     */

    offset_ += len;

    if (theFile->error()) {
        debugs(79,2, " detected an error, will try to close");
        tryClosing();
    }

    /*
     * HNO 2009-07-24
     * Kick any pending write/close operations alive
     */
    drainWriteQueue();
}

void
Fs::Ufs::UFSStoreState::doCloseCallback(int errflag)
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
    callback = nullptr;

    void *cbdata;

    if (cbdataReferenceValidDone(callback_data, &cbdata) && theCallback)
        theCallback(cbdata, errflag, this);

    /*
     * We are finished with theFile since the lower layer signalled
     * us that the file has been closed.  This must be the last line,
     * as theFile may be the only object holding us in memory.
     */
    theFile = nullptr; // refcounted
}

/* ============= THE REAL UFS CODE ================ */

Fs::Ufs::UFSStoreState::UFSStoreState(SwapDir * SD, StoreEntry * anEntry, STIOCB * cbIo, void *data) :
    StoreIOState(cbIo, data),
    opening(false),
    creating(false),
    closing(false),
    reading(false),
    writing(false),
    read_buf(nullptr)
{
    // StoreIOState inherited members
    swap_filen = anEntry->swap_filen;
    swap_dirn = SD->index;
    e = anEntry;

    // our flags
    flags.write_draining = false;
    flags.try_closing = false;
}

Fs::Ufs::UFSStoreState::~UFSStoreState()
{
    assert(pending_reads.empty());
    assert(pending_writes.empty());
}

void
Fs::Ufs::UFSStoreState::freePending()
{
    while (!pending_reads.empty())
        pending_reads.pop();
    debugs(79, 3, "freed pending reads");

    while (!pending_writes.empty())
        pending_writes.pop();
    debugs(79, 3, "freed pending writes");
}

bool
Fs::Ufs::UFSStoreState::kickReadQueue()
{
    if (pending_reads.empty())
        return false;

    auto &q = pending_reads.front();

    debugs(79, 3, "reading queued request of " << q.size << " bytes");

    bool result = true;
    void *cbdata;
    if (cbdataReferenceValidDone(q.callback_data, &cbdata)) {
        read_(q.buf, q.size, q.offset, q.callback, cbdata);
    } else {
        debugs(79, 2, "this=" << (void*)this << " cbdataReferenceValidDone returned false." <<
               " closing: " << closing << " flags.try_closing: " << flags.try_closing);
        result = false;
    }

    pending_reads.pop(); // erase the front object
    return result;
}

/*
 * DPW 2006-05-24
 * drainWriteQueue() is a loop around doWrite().
 */
void
Fs::Ufs::UFSStoreState::drainWriteQueue()
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

    if (!theFile || !theFile->canWrite())
        return;

    flags.write_draining = true;

    while (!pending_writes.empty())
        doWrite();

    flags.write_draining = false;

    if (flags.try_closing)
        tryClosing();
}

/*
 * DPW 2006-05-24
 * This blows.  DiskThreadsDiskFile::close() won't actually do the close
 * if ioInProgress() is true.  So we have to check it here.  Maybe someday
 * DiskThreadsDiskFile::close() will be modified to have a return value,
 * or will remember to do the close for us.
 */
void
Fs::Ufs::UFSStoreState::tryClosing()
{
    debugs(79,3, this << " tryClosing()" <<
           " closing = " << closing <<
           " flags.try_closing = " << flags.try_closing <<
           " ioInProgress = " << theFile->ioInProgress());

    if (theFile->ioInProgress()) {
        debugs(79, 3, this <<
               " won't close since ioInProgress is true, bailing");
        flags.try_closing = true;
        return;
    }

    closing = true;
    flags.try_closing = false;
    theFile->close();
}

