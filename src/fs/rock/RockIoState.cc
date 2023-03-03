/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
                       StoreIOState::STIOCB *cbIo,
                       void *data) :
    StoreIOState(cbIo, data),
    readableAnchor_(nullptr),
    writeableAnchor_(nullptr),
    splicingPoint(-1),
    staleSplicingPointNext(-1),
    dir(aDir),
    slotSize(dir->slotSize),
    objOffset(0),
    sidFirst(-1),
    sidPrevious(-1),
    sidCurrent(-1),
    sidNext(-1),
    requestsSent(0),
    repliesReceived(0),
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
    theFile = nullptr;

    e->unlock("rock I/O");
}

void
Rock::IoState::file(const RefCount<DiskFile> &aFile)
{
    assert(!theFile);
    assert(aFile != nullptr);
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

    assert(theFile != nullptr);
    assert(coreOff >= 0);

    bool writerLeft = readAnchor().writerHalted; // before the sidCurrent change

    // if we are dealing with the first read or
    // if the offset went backwords, start searching from the beginning
    if (sidCurrent < 0 || coreOff < objOffset) {
        // readers do not need sidFirst but set it for consistency/triage sake
        sidCurrent = sidFirst = readAnchor().start;
        objOffset = 0;
    }

    while (sidCurrent >= 0 && coreOff >= objOffset + currentReadableSlice().size) {
        writerLeft = readAnchor().writerHalted; // before the sidCurrent change
        objOffset += currentReadableSlice().size;
        sidCurrent = currentReadableSlice().next;
    }

    assert(read.callback == nullptr);
    assert(read.callback_data == nullptr);
    read.callback = cb;
    read.callback_data = cbdataReference(data);

    // quit if we cannot read what they want, and the writer cannot add more
    if (sidCurrent < 0 && writerLeft) {
        debugs(79, 5, "quitting at " << coreOff << " in " << *e);
        callReaderBack(buf, -1);
        return;
    }

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
    const auto start = diskOffset + sizeof(DbCellHeader) + coreOff - objOffset;
    const auto id = ++requestsSent;
    const auto request = new ReadRequest(::ReadRequest(buf, start, len), this, id);
    theFile->read(request);
}

void
Rock::IoState::handleReadCompletion(Rock::ReadRequest &request, const int rlen, const int errFlag)
{
    if (errFlag != DISK_OK || rlen < 0) {
        debugs(79, 3, errFlag << " failure for " << *e);
        return callReaderBack(request.buf, -1);
    }

    if (!expectedReply(request.id))
        return callReaderBack(request.buf, -1);

    debugs(79, 5, '#' << request.id << " read " << rlen << " bytes at " << offset_ << " for " << *e);
    offset_ += rlen;
    callReaderBack(request.buf, rlen);
}

/// report (already sanitized/checked) I/O results to the read initiator
void
Rock::IoState::callReaderBack(const char *buf, int rlen)
{
    splicingPoint = rlen >= 0 ? sidCurrent : -1;
    if (splicingPoint < 0)
        staleSplicingPointNext = -1;
    else
        staleSplicingPointNext = currentReadableSlice().next;
    StoreIOState::STRCB *callb = read.callback;
    assert(callb);
    read.callback = nullptr;
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

    // either this is the first write or append;
    // we do not support write gaps or rewrites
    assert(!coreOff || coreOff == -1);

    // throw if an accepted unknown-size entry grew too big or max-size changed
    Must(static_cast<uint64_t>(offset_ + size) <= static_cast<uint64_t>(dir->maxObjectSize()));

    // buffer incoming data in slot buffer and write overflowing or final slots
    // quit when no data left or we stopped writing on reentrant error
    while (size > 0 && theFile != nullptr) {
        const size_t processed = writeToBuffer(buf, size);
        buf += processed;
        size -= processed;
        const bool overflow = size > 0;

        // We do not write a full buffer without overflow because
        // we do not want to risk writing a payload-free slot on EOF.
        if (overflow) {
            Must(sidNext < 0);
            sidNext = dir->reserveSlotForWriting();
            assert(sidNext >= 0);
            writeToDisk();
            Must(sidNext < 0); // short sidNext lifetime simplifies code logic
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
        // eventually, writeToDisk() will fill this header space
        theBuf.appended(sizeof(DbCellHeader));
    }

    size_t forCurrentSlot = min(size, static_cast<size_t>(theBuf.spaceSize()));
    theBuf.append(buf, forCurrentSlot);
    offset_ += forCurrentSlot; // so that Core thinks we wrote it
    return forCurrentSlot;
}

/// write what was buffered during write() calls
void
Rock::IoState::writeToDisk()
{
    assert(theFile != nullptr);
    assert(theBuf.size >= sizeof(DbCellHeader));

    assert((sidFirst < 0) == (sidCurrent < 0));
    if (sidFirst < 0) // this is the first disk write
        sidCurrent = sidFirst = dir->reserveSlotForWriting();

    // negative sidNext means this is the last write request for this entry
    const bool lastWrite = sidNext < 0;
    // here, eof means that we are writing the right-most entry slot
    const bool eof = lastWrite &&
                     // either not updating or the updating reader has loaded everything
                     (touchingStoreEntry() || staleSplicingPointNext < 0);
    debugs(79, 5, "sidCurrent=" << sidCurrent << " sidNext=" << sidNext << " eof=" << eof);

    // TODO: if DiskIO module is mmap-based, we should be writing whole pages
    // to avoid triggering read-page;new_head+old_tail;write-page overheads

    assert(!eof || sidNext < 0); // no slots after eof

    // finalize db cell header
    DbCellHeader header;
    memcpy(header.key, e->key, sizeof(header.key));
    header.firstSlot = sidFirst;

    const auto lastUpdatingWrite = lastWrite && !touchingStoreEntry();
    assert(!lastUpdatingWrite || sidNext < 0);
    header.nextSlot = lastUpdatingWrite ? staleSplicingPointNext : sidNext;

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
    debugs(79, 5, swap_filen << " at " << diskOffset << '+' <<
           theBuf.size);
    const auto id = ++requestsSent;
    WriteRequest *const r = new WriteRequest(
        ::WriteRequest(static_cast<char*>(wBuf), diskOffset, theBuf.size,
                       memFreeBufFunc(wBufCap)), this, id);
    r->sidCurrent = sidCurrent;
    r->sidPrevious = sidPrevious;
    r->eof = lastWrite;

    sidPrevious = sidCurrent;
    sidCurrent = sidNext; // sidNext may be cleared/negative already
    sidNext = -1;

    theBuf.clear();

    // theFile->write may call writeCompleted immediately
    theFile->write(r);
}

bool
Rock::IoState::expectedReply(const IoXactionId receivedId)
{
    Must(requestsSent); // paranoid: we sent some requests
    Must(receivedId); // paranoid: the request was sent by some sio
    Must(receivedId <= requestsSent); // paranoid: within our range
    ++repliesReceived;
    const auto expectedId = repliesReceived;
    if (receivedId == expectedId)
        return true;

    debugs(79, 3, "no; expected reply #" << expectedId <<
           ", but got #" << receivedId);
    return false;
}

void
Rock::IoState::finishedWriting(const int errFlag)
{
    if (sidCurrent >= 0) {
        dir->noteFreeMapSlice(sidCurrent);
        sidCurrent = -1;
    }
    if (sidNext >= 0) {
        dir->noteFreeMapSlice(sidNext);
        sidNext = -1;
    }

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
           " leftovers: " << theBuf.size <<
           " after " << requestsSent << '/' << repliesReceived <<
           " callback: " << callback);

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
        try {
            writeToDisk(); // flush last, yet unwritten slot to disk
            return; // writeCompleted() will callBack()
        }
        catch (...) {
            debugs(79, 2, "db flush error: " << CurrentException);
            // TODO: Move finishedWriting() into SwapDir::writeError().
            dir->writeError(*this);
            finishedWriting(DISK_ERROR);
        }
        return;

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
        callback(nullptr),
        callback_data(nullptr),
        errflag(err),
        sio(anSio) {

        callback = cb;
        callback_data = cbdataReference(data);
    }

    StoreIOStateCb(const StoreIOStateCb &cb):
        callback(nullptr),
        callback_data(nullptr),
        errflag(cb.errflag),
        sio(cb.sio) {

        callback = cb.callback;
        callback_data = cbdataReference(cb.callback_data);
    }

    ~StoreIOStateCb() override {
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

    void print(std::ostream &os) const override {
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
    debugs(79,3, "errflag=" << errflag);
    theFile = nullptr;

    AsyncCall::Pointer call = asyncCall(79,3, "SomeIoStateCloseCb",
                                        StoreIOStateCb(callback, callback_data, errflag, this));
    ScheduleCallHere(call);

    callback = nullptr;
    cbdataReferenceDone(callback_data);
}

