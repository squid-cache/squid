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

Rock::IoState::IoState(SwapDir &aDir,
                       StoreEntry *anEntry,
                       StoreIOState::STFNCB *cbFile,
                       StoreIOState::STIOCB *cbIo,
                       void *data):
        dbSlot(NULL),
        dir(aDir),
        slotSize(dir.max_objsize),
        objOffset(0)
{
    e = anEntry;
    // swap_filen, swap_dirn and diskOffset are set by the caller
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

    Ipc::Mem::PageId pageId;
    pageId.pool = dir.index;
    if (coreOff < objOffset) { // rewind
        pageId.number = dbSlot->firstSlot;
        dbSlot = &dir.dbSlot(pageId);
        objOffset = 0;
    }

    while (coreOff >= objOffset + dbSlot->payloadSize) {
        objOffset += dbSlot->payloadSize;
        pageId.number = dbSlot->nextSlot;
        assert(pageId); // XXX: should be an error?
        dbSlot = &dir.dbSlot(pageId);
    }
    if (pageId)
        diskOffset = dir.diskOffset(pageId);

    offset_ = coreOff;
    len = min(len,
        static_cast<size_t>(objOffset + dbSlot->payloadSize - coreOff));

    assert(read.callback == NULL);
    assert(read.callback_data == NULL);
    read.callback = cb;
    read.callback_data = cbdataReference(data);

    theFile->read(new ReadRequest(::ReadRequest(buf,
        diskOffset + sizeof(DbCellHeader) + coreOff - objOffset, len), this));
}

// We only write data when full slot is accumulated or when close() is called.
// We buffer, in part, to avoid forcing OS to _read_ old unwritten portions
// of the slot when the write does not end at the page or sector boundary.
void
Rock::IoState::write(char const *buf, size_t size, off_t coreOff, FREE *dtor)
{
    assert(dbSlot);

    if (theBuf.isNull()) {
        theBuf.init(min(size + sizeof(DbCellHeader), slotSize), slotSize);
        theBuf.appended(sizeof(DbCellHeader)); // will fill header in doWrite
    }

    if (size <= static_cast<size_t>(theBuf.spaceSize()))
        theBuf.append(buf, size);
    else {
        Ipc::Mem::PageId pageId;
        if (!dir.popDbSlot(pageId)) {
            debugs(79, DBG_IMPORTANT, "WARNING: Rock cache_dir '" << dir.path <<
                   "' run out of DB slots");
            dir.writeError(swap_filen);
            // XXX: do we need to destroy buf on error?
            if (dtor)
                (dtor)(const_cast<char*>(buf)); // cast due to a broken API?
            // XXX: do we need to call callback on error?
            callBack(DISK_ERROR);
            return;
        }
        DbCellHeader &nextDbSlot = dir.dbSlot(pageId);
        memcpy(nextDbSlot.key, dbSlot->key, sizeof(nextDbSlot.key));
        nextDbSlot.firstSlot = dbSlot->firstSlot;
        nextDbSlot.nextSlot = 0;
        nextDbSlot.version = dbSlot->version;
        nextDbSlot.payloadSize = 0;

        dbSlot->nextSlot = pageId.number;

        const size_t left = size - theBuf.spaceSize();
        offset_ += theBuf.spaceSize(); // so that Core thinks we wrote it
        theBuf.append(buf, theBuf.spaceSize());

        doWrite();

        dbSlot = &nextDbSlot;
        diskOffset = dir.diskOffset(pageId);
        theBuf.init(min(left, slotSize), slotSize);
        write(buf + size - left, left, -1, NULL);
    }

    if (dtor)
        (dtor)(const_cast<char*>(buf)); // cast due to a broken API?
}

// write what was buffered during write() calls
void
Rock::IoState::doWrite(const bool isLast)
{
    assert(theFile != NULL);
    assert(!theBuf.isNull());

    // TODO: if DiskIO module is mmap-based, we should be writing whole pages
    // to avoid triggering read-page;new_head+old_tail;write-page overheads

    debugs(79, 5, HERE << swap_filen << " at " << diskOffset << '+' <<
           theBuf.contentSize());

    dbSlot->payloadSize = theBuf.contentSize() - sizeof(DbCellHeader);
    memcpy(theBuf.content(), dbSlot, sizeof(DbCellHeader));

    assert(static_cast<size_t>(theBuf.contentSize()) <= slotSize);
    // theFile->write may call writeCompleted immediatelly
    WriteRequest *const r = new WriteRequest(
        ::WriteRequest(theBuf.content(), diskOffset, theBuf.contentSize(),
                       theBuf.freeFunc()), this, isLast);
    theFile->write(r);
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
        doWrite(true);
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

