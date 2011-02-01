/*
 * $Id$
 *
 * DEBUG: section 79    Disk IO Routines
 */

#include "Parsing.h"
#include "DiskIO/DiskIOModule.h"
#include "DiskIO/DiskIOStrategy.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockIoState.h"
#include "fs/rock/RockIoRequests.h"
#include "fs/rock/RockSwapDir.h"

Rock::IoState::IoState(SwapDir *dir,
    StoreEntry *anEntry,
    StoreIOState::STFNCB *cbFile,
    StoreIOState::STIOCB *cbIo,
    void *data):
    slotSize(0),
    entrySize(0)
{
    e = anEntry;
    swap_filen = e->swap_filen;
    swap_dirn = dir->index;
    slotSize = dir->max_objsize;
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
Rock::IoState::read_(char *buf, size_t len, off_t off, STRCB *cb, void *data)
{
    assert(theFile != NULL);
    assert(theFile->canRead());

    // Core specifies buffer length, but we must not exceed stored entry size
    assert(off >= 0);
    assert(entrySize >= 0);
    const int64_t offset = static_cast<int64_t>(off);
    assert(offset <= entrySize);
    if (offset + (int64_t)len > entrySize)
        len = entrySize - offset;

    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    read.callback = cb;
    read.callback_data = cbdataReference(data);

    theFile->read(new ReadRequest(::ReadRequest(buf, offset_ + offset, len), this));
}

// We only buffer data here; we actually write when close() is called.
// We buffer, in part, to avoid forcing OS to _read_ old unwritten portions
// of the slot when the write does not end at the page or sector boundary.
void
Rock::IoState::write(char const *buf, size_t size, off_t offset, FREE *dtor)
{
    // TODO: move to create?
    if (!offset) {
        assert(theBuf.isNull());
        assert(entrySize >= 0);
        theBuf.init(min(entrySize, slotSize), slotSize);
    } else {
        // Core uses -1 offset as "append". Sigh.
        assert(offset == -1);
        assert(!theBuf.isNull());
    }

    theBuf.append(buf, size);

    if (dtor)
        (dtor)(const_cast<char*>(buf)); // cast due to a broken API?
}

// write what was buffered during write() calls
void
Rock::IoState::startWriting()
{
    assert(theFile != NULL);
    assert(theFile->canWrite());
    assert(!theBuf.isNull());

    // TODO: if DiskIO module is mmap-based, we should be writing whole pages
    // to avoid triggering read-page;new_head+old_tail;write-page overheads

    debugs(79, 5, HERE << swap_filen << " at " << offset_ << '+' <<
        theBuf.contentSize());

    assert(theBuf.contentSize() <= slotSize);
    // theFile->write may call writeCompleted immediatelly
    theFile->write(new WriteRequest(::WriteRequest(theBuf.content(), offset_,
        theBuf.contentSize(), theBuf.freeFunc()), this));
}

// 
void
Rock::IoState::finishedWriting(const int errFlag)
{
    callBack(errFlag);
}

void
Rock::IoState::close()
{
    debugs(79, 3, HERE << swap_filen << " at " << offset_);
    if (!theBuf.isNull())
        startWriting();
    else
        callBack(0);
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

