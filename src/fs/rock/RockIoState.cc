/*
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "MemObject.h"
#include "Parsing.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockIoState.h"
#include "fs/rock/RockIoRequests.h"
#include "fs/rock/RockSwapDir.h"
#include "globals.h"

Rock::IoState::IoState(SwapDir *dir,
                       StoreEntry *anEntry,
                       StoreIOState::STFNCB *cbFile,
                       StoreIOState::STIOCB *cbIo,
                       void *data):
        slotSize(0),
        diskOffset(-1),
        payloadEnd(-1)
{
    e = anEntry;
    // swap_filen, swap_dirn, diskOffset, and payloadEnd are set by the caller
    slotSize = dir->maxObjectSize();
    file_callback = cbFile;
    callback = cbIo;
    callback_data = cbdataReference(data);
    ++store_open_disk_fd; // TODO: use a dedicated counter?
    //theFile is set by SwapDir because it depends on DiskIOStrategy
}

Rock::IoState::~IoState()
{
    --store_open_disk_fd;
    if (callback_data)
        cbdataReferenceDone(callback_data);
    theFile = NULL;
}

void
Rock::IoState::file(const RefCount<DiskFile> &aFile)
{
    assert(!theFile);
    assert(aFile != NULL);
    theFile = aFile;
}

void
Rock::IoState::read_(char *buf, size_t len, off_t coreOff, STRCB *cb, void *data)
{
    assert(theFile != NULL);
    assert(coreOff >= 0);
    offset_ = coreOff;

    // we skip our cell header; it is only read when building the map
    const int64_t cellOffset = sizeof(DbCellHeader) +
                               static_cast<int64_t>(coreOff);
    assert(cellOffset <= payloadEnd);

    // Core specifies buffer length, but we must not exceed stored entry size
    if (cellOffset + (int64_t)len > payloadEnd)
        len = payloadEnd - cellOffset;

    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    read.callback = cb;
    read.callback_data = cbdataReference(data);

    theFile->read(new ReadRequest(
                      ::ReadRequest(buf, diskOffset + cellOffset, len), this));
}

// We only buffer data here; we actually write when close() is called.
// We buffer, in part, to avoid forcing OS to _read_ old unwritten portions
// of the slot when the write does not end at the page or sector boundary.
void
Rock::IoState::write(char const *buf, size_t size, off_t coreOff, FREE *dtor)
{
    // TODO: move to create?
    if (!coreOff) {
        assert(theBuf.isNull());
        assert(payloadEnd <= slotSize);
        theBuf.init(min(payloadEnd, slotSize), slotSize);
        // start with our header; TODO: consider making it a trailer
        DbCellHeader header;
        assert(static_cast<int64_t>(sizeof(header)) <= payloadEnd);
        header.payloadSize = payloadEnd - sizeof(header);
        theBuf.append(reinterpret_cast<const char*>(&header), sizeof(header));
    } else {
        // Core uses -1 offset as "append". Sigh.
        assert(coreOff == -1);
        assert(!theBuf.isNull());
    }

    theBuf.append(buf, size);
    offset_ += size; // so that Core thinks we wrote it

    if (dtor)
        (dtor)(const_cast<char*>(buf)); // cast due to a broken API?
}

// write what was buffered during write() calls
void
Rock::IoState::startWriting()
{
    assert(theFile != NULL);
    assert(!theBuf.isNull());

    // TODO: if DiskIO module is mmap-based, we should be writing whole pages
    // to avoid triggering read-page;new_head+old_tail;write-page overheads

    debugs(79, 5, HERE << swap_filen << " at " << diskOffset << '+' <<
           theBuf.contentSize());

    assert(theBuf.contentSize() <= slotSize);
    // theFile->write may call writeCompleted immediatelly
    theFile->write(new WriteRequest(::WriteRequest(theBuf.content(),
                                    diskOffset, theBuf.contentSize(), theBuf.freeFunc()), this));
}

//
void
Rock::IoState::finishedWriting(const int errFlag)
{
    // we incremented offset_ while accumulating data in write()
    callBack(errFlag);
}

void
Rock::IoState::close(int how)
{
    debugs(79, 3, HERE << swap_filen << " accumulated: " << offset_ <<
           " how=" << how);
    if (how == wroteAll && !theBuf.isNull())
        startWriting();
    else
        callBack(how == writerGone ? DISK_ERROR : 0); // TODO: add DISK_CALLER_GONE
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

    void dial(AsyncCall &call) {
        void *cbd;
        if (cbdataReferenceValidDone(callback_data, &cbd) && callback)
            callback(cbd, errflag, sio.getRaw());
    }

    bool canDial(AsyncCall &call) const {
        return cbdataReferenceValid(callback_data) && callback;
    }

    virtual void print(std::ostream &os) const {
        os << '(' << callback_data << ", err=" << errflag << ')';
    }

private:
    StoreIOStateCb &operator =(const StoreIOStateCb &cb); // not defined

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

