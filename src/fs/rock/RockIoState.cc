/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "base/TextException.h"
#include "CollapsedForwarding.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockIoRequests.h"
#include "fs/rock/RockIoState.h"
#include "fs/rock/RockSwapDir.h"
#include "globals.h"
#include "MemObject.h"
#include "Parsing.h"
#include "Transients.h"

Rock::IoState::IoState(Rock::SwapDir::Pointer &aDir,
                       StoreEntry *anEntry,
                       StoreIOState::STFNCB *cbFile,
                       StoreIOState::STIOCB *cbIo,
                       void *data) :
    StoreIOState(cbFile, cbIo, data),
    readableAnchor_(NULL),
    writeableAnchor_(NULL),
    splicingPoint(-1),
    staleSplicingPointNext(-1),
    dir(aDir),
    slotSize(dir->slotSize),
    objOffset(0),
    sidCurrent(-1),
    theBuf(dir->slotSize)
{
    e = anEntry;
    e->lock("rock I/O");
    // anchor, swap_filen, and swap_dirn are set by the caller
    ++store_open_disk_fd; // TODO: use a dedicated counter?
    //theFile is set by SwapDir because it depends on DiskIOStrategy
}

Rock::IoState::~IoState()
{
    --store_open_disk_fd;

    // The dir map entry may still be open for reading at the point because
    // the map entry lock is associated with StoreEntry, not IoState.
    // assert(!readableAnchor_);
    assert(shutting_down || !writeableAnchor_);

    if (callback_data)
        cbdataReferenceDone(callback_data);
    theFile = NULL;

    e->unlock("rock I/O");
}

void
Rock::IoState::file(const RefCount<DiskFile> &aFile)
{
    assert(!theFile);
    assert(aFile != NULL);
    theFile = aFile;
}

const Ipc::StoreMapAnchor &
Rock::IoState::readAnchor() const
{
    assert(readableAnchor_);
    return *readableAnchor_;
}

Ipc::StoreMapAnchor &
Rock::IoState::writeAnchor()
{
    assert(writeableAnchor_);
    return *writeableAnchor_;
}

/// convenience wrapper returning the map slot we are reading now
const Ipc::StoreMapSlice &
Rock::IoState::currentReadableSlice() const
{
    return dir->map->readableSlice(swap_filen, sidCurrent);
}

void
Rock::IoState::read_(char *buf, size_t len, off_t coreOff, STRCB *cb, void *data)
{
    debugs(79, 7, swap_filen << " reads from " << coreOff);

    assert(theFile != NULL);
    assert(coreOff >= 0);

    // if we are dealing with the first read or
    // if the offset went backwords, start searching from the beginning
    if (sidCurrent < 0 || coreOff < objOffset) {
        sidCurrent = readAnchor().start;
        objOffset = 0;
    }

    while (sidCurrent >= 0 && coreOff >= objOffset + currentReadableSlice().size) {
        objOffset += currentReadableSlice().size;
        sidCurrent = currentReadableSlice().next;
    }

    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    read.callback = cb;
    read.callback_data = cbdataReference(data);

    // punt if read offset is too big (because of client bugs or collapsing)
    if (sidCurrent < 0) {
        debugs(79, 5, "no " << coreOff << " in " << *e);
        callReaderBack(buf, 0);
        return;
    }

    offset_ = coreOff;
    len = min(len,
              static_cast<size_t>(objOffset + currentReadableSlice().size - coreOff));
    const uint64_t diskOffset = dir->diskOffset(sidCurrent);
    theFile->read(new ReadRequest(::ReadRequest(buf,
                                  diskOffset + sizeof(DbCellHeader) + coreOff - objOffset, len), this));
}

void
Rock::IoState::callReaderBack(const char *buf, int rlen)
{
    debugs(79, 5, rlen << " bytes for " << *e);
    splicingPoint = rlen >= 0 ? sidCurrent : -1;
    if (splicingPoint < 0)
        staleSplicingPointNext = -1;
    else
        staleSplicingPointNext = currentReadableSlice().next;
    StoreIOState::STRCB *callb = read.callback;
    assert(callb);
    read.callback = NULL;
    void *cbdata;
    if (cbdataReferenceValidDone(read.callback_data, &cbdata))
        callb(cbdata, buf, rlen, this);
}

/// wraps tryWrite() to handle deep write failures centrally and safely
bool
Rock::IoState::write(char const *buf, size_t size, off_t coreOff, FREE *dtor)
{
    bool success = false;
    try {
        tryWrite(buf, size, coreOff);
        success = true;
    } catch (const std::exception &ex) { // TODO: should we catch ... as well?
        debugs(79, 2, "db write error: " << ex.what());
        dir->writeError(*this);
        finishedWriting(DISK_ERROR);
        // 'this' might be gone beyond this point; fall through to free buf
    }

    // careful: 'this' might be gone here

    if (dtor)
        (dtor)(const_cast<char*>(buf)); // cast due to a broken API?

    return success;
}

/**
 * Possibly send data to be written to disk:
 * We only write data when full slot is accumulated or when close() is called.
 * We buffer, in part, to avoid forcing OS to _read_ old unwritten portions of
 * the slot when the write does not end at the page or sector boundary.
 */
void
Rock::IoState::tryWrite(char const *buf, size_t size, off_t coreOff)
{
    debugs(79, 7, swap_filen << " writes " << size << " more");

    // either this is the first write or append; we do not support write gaps
    assert(!coreOff || coreOff == -1);

    // throw if an accepted unknown-size entry grew too big or max-size changed
    Must(static_cast<uint64_t>(offset_ + size) <= static_cast<uint64_t>(dir->maxObjectSize()));

    // allocate the first slice during the first write
    if (!coreOff) {
        assert(sidCurrent < 0);
        sidCurrent = dir->reserveSlotForWriting(); // throws on failures
        assert(sidCurrent >= 0);
        writeAnchor().start = sidCurrent;
    }

    // buffer incoming data in slot buffer and write overflowing or final slots
    // quit when no data left or we stopped writing on reentrant error
    while (size > 0 && theFile != NULL) {
        assert(sidCurrent >= 0);
        const size_t processed = writeToBuffer(buf, size);
        buf += processed;
        size -= processed;
        const bool overflow = size > 0;

        // We do not write a full buffer without overflow because
        // we would not yet know what to set the nextSlot to.
        if (overflow) {
            const auto sidNext = dir->reserveSlotForWriting(); // throws
            assert(sidNext >= 0);
            writeToDisk(sidNext);
            // } else if (Store::Root().transientReaders(*e)) {
            // XXX: Partial writes cannot be read -- no map->startAppending()!
            // XXX: Partial writes confuse SwapDir::droppedEarlierRequest(),
            // resulting in released entries and, hence, misses and CF retries.
            // XXX: The effective benefit of partial writes is reduced by
            // doPages() buffering SM_PAGE_SIZE*n leftovers.

            // // write partial buffer for all remote hit readers to see
            // writeBufToDisk(-1, false, false);
        }
    }

}

/// Buffers incoming data for the current slot.
/// \return the number of bytes buffered
size_t
Rock::IoState::writeToBuffer(char const *buf, size_t size)
{
    // do not buffer a cell header for nothing
    if (!size)
        return 0;

    if (!theBuf.size) {
        // will fill the header in writeToDisk when the next slot is known
        theBuf.appended(sizeof(DbCellHeader));
    }

    size_t forCurrentSlot = min(size, static_cast<size_t>(theBuf.spaceSize()));
    theBuf.append(buf, forCurrentSlot);
    offset_ += forCurrentSlot; // so that Core thinks we wrote it
    return forCurrentSlot;
}

/// write what was buffered during write() calls
/// negative sidNext means this is the last write request for this entry
void
Rock::IoState::writeToDisk(const SlotId sidNextProposal)
{
    assert(theFile != NULL);
    assert(theBuf.size >= sizeof(DbCellHeader));

    const bool lastWrite = sidNextProposal < 0;
    const bool eof = lastWrite &&
                     // either not updating or the updating reader has loaded everything
                     (touchingStoreEntry() || staleSplicingPointNext < 0);
    // approve sidNextProposal unless _updating_ the last slot
    const SlotId sidNext = (!touchingStoreEntry() && lastWrite) ?
                           staleSplicingPointNext : sidNextProposal;
    debugs(79, 5, "sidNext:" << sidNextProposal << "=>" << sidNext << " eof=" << eof);

    // TODO: if DiskIO module is mmap-based, we should be writing whole pages
    // to avoid triggering read-page;new_head+old_tail;write-page overheads

    writeBufToDisk(sidNext, eof, lastWrite);
    theBuf.clear();

    sidCurrent = sidNext;
}

/// creates and submits a request to write current slot buffer to disk
/// eof is true if and only this is the last slot
void
Rock::IoState::writeBufToDisk(const SlotId sidNext, const bool eof, const bool lastWrite)
{
    // no slots after the last/eof slot (but partial slots may have a nil next)
    assert(!eof || sidNext < 0);

    // finalize db cell header
    DbCellHeader header;
    memcpy(header.key, e->key, sizeof(header.key));
    header.firstSlot = writeAnchor().start;
    header.nextSlot = sidNext;
    header.payloadSize = theBuf.size - sizeof(DbCellHeader);
    header.entrySize = eof ? offset_ : 0; // storeSwapOutFileClosed sets swap_file_sz after write
    header.version = writeAnchor().basics.timestamp;

    // copy finalized db cell header into buffer
    memcpy(theBuf.mem, &header, sizeof(DbCellHeader));

    // and now allocate another buffer for the WriteRequest so that
    // we can support concurrent WriteRequests (and to ease cleaning)
    // TODO: should we limit the number of outstanding requests?
    size_t wBufCap = 0;
    void *wBuf = memAllocBuf(theBuf.size, &wBufCap);
    memcpy(wBuf, theBuf.mem, theBuf.size);

    const uint64_t diskOffset = dir->diskOffset(sidCurrent);
    debugs(79, 5, HERE << swap_filen << " at " << diskOffset << '+' <<
           theBuf.size);

    WriteRequest *const r = new WriteRequest(
        ::WriteRequest(static_cast<char*>(wBuf), diskOffset, theBuf.size,
                       memFreeBufFunc(wBufCap)), this);
    r->sidCurrent = sidCurrent;
    r->sidNext = sidNext;
    r->eof = lastWrite;

    // theFile->write may call writeCompleted immediatelly
    theFile->write(r);
}

void
Rock::IoState::finishedWriting(const int errFlag)
{
    // we incremented offset_ while accumulating data in write()
    // we do not reset writeableAnchor_ here because we still keep the lock
    if (touchingStoreEntry())
        CollapsedForwarding::Broadcast(*e);
    callBack(errFlag);
}

void
Rock::IoState::close(int how)
{
    debugs(79, 3, swap_filen << " offset: " << offset_ << " how: " << how <<
           " buf: " << theBuf.size << " callback: " << callback);

    if (!theFile) {
        debugs(79, 3, "I/O already canceled");
        assert(!callback);
        // We keep writeableAnchor_ after callBack() on I/O errors.
        assert(!readableAnchor_);
        return;
    }

    switch (how) {
    case wroteAll:
        assert(theBuf.size > 0); // we never flush last bytes on our own
        writeToDisk(-1); // flush last, yet unwritten slot to disk
        return; // writeCompleted() will callBack()

    case writerGone:
        dir->writeError(*this); // abort a partially stored entry
        finishedWriting(DISK_ERROR);
        return;

    case readerDone:
        callBack(0);
        return;
    }
}

/// close callback (STIOCB) dialer: breaks dependencies and
/// counts IOState concurrency level
class StoreIOStateCb: public CallDialer
{
public:
    StoreIOStateCb(StoreIOState::STIOCB *cb, void *data, int err, const Rock::IoState::Pointer &anSio):
        callback(NULL),
        callback_data(NULL),
        errflag(err),
        sio(anSio) {

        callback = cb;
        callback_data = cbdataReference(data);
    }

    StoreIOStateCb(const StoreIOStateCb &cb):
        callback(NULL),
        callback_data(NULL),
        errflag(cb.errflag),
        sio(cb.sio) {

        callback = cb.callback;
        callback_data = cbdataReference(cb.callback_data);
    }

    virtual ~StoreIOStateCb() {
        cbdataReferenceDone(callback_data); // may be nil already
    }

    void dial(AsyncCall &) {
        void *cbd;
        if (cbdataReferenceValidDone(callback_data, &cbd) && callback)
            callback(cbd, errflag, sio.getRaw());
    }

    bool canDial(AsyncCall &) const {
        return cbdataReferenceValid(callback_data) && callback;
    }

    virtual void print(std::ostream &os) const {
        os << '(' << callback_data << ", err=" << errflag << ')';
    }

private:
    StoreIOStateCb &operator =(const StoreIOStateCb &); // not defined

    StoreIOState::STIOCB *callback;
    void *callback_data;
    int errflag;
    Rock::IoState::Pointer sio;
};

void
Rock::IoState::callBack(int errflag)
{
    debugs(79,3, HERE << "errflag=" << errflag);
    theFile = NULL;

    AsyncCall::Pointer call = asyncCall(79,3, "SomeIoStateCloseCb",
                                        StoreIOStateCb(callback, callback_data, errflag, this));
    ScheduleCallHere(call);

    callback = NULL;
    cbdataReferenceDone(callback_data);
}

