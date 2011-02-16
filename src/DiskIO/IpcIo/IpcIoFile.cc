/*
 * $Id$
 *
 * DEBUG: section 47    Store Directory Routines
 */

#include "config.h"
#include "base/TextException.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/IpcIo/IpcIoFile.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "ipc/Messages.h"
#include "ipc/Port.h"
#include "ipc/StrandSearch.h"
#include "ipc/UdsOp.h"

CBDATA_CLASS_INIT(IpcIoFile);

IpcIoFile::DiskerQueue *IpcIoFile::diskerQueue = NULL;
IpcIoFile::IpcIoFiles IpcIoFile::ipcIoFiles;

static bool DiskerOpen(const String &path, int flags, mode_t mode);
static void DiskerClose(const String &path);


IpcIoFile::IpcIoFile(char const *aDb):
    dbName(aDb),
    diskId(-1),
    workerQueue(NULL),
    error_(false),
    lastRequestId(0),
    olderRequests(&requestMap1),
    newerRequests(&requestMap2),
    timeoutCheckScheduled(false)
{
}

IpcIoFile::~IpcIoFile()
{
}

void
IpcIoFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    debugs(0,0,HERE);
    ioRequestor = callback;
    Must(diskId < 0); // we do not know our disker yet
    Must(!diskerQueue && !workerQueue);

    if (IamDiskProcess()) {
        error_ = !DiskerOpen(dbName, flags, mode);
        if (error_)
            return;

        // XXX: make capacity configurable
        diskerQueue = new DiskerQueue(dbName.termedBuf(), Config.workers, 1024);
        ipcIoFiles.insert(std::make_pair(KidIdentifier, this));

        Ipc::HereIamMessage ann(Ipc::StrandCoord(KidIdentifier, getpid()));
        ann.strand.tag = dbName;
        Ipc::TypedMsgHdr message;
        ann.pack(message);
        SendMessage(Ipc::coordinatorAddr, message);

        ioRequestor->ioCompletedNotification();
        return;
    }

    Ipc::StrandSearchRequest request;
    request.requestorId = KidIdentifier;
    request.tag = dbName;

    Ipc::TypedMsgHdr msg;
    request.pack(msg);
    Ipc::SendMessage(Ipc::coordinatorAddr, msg);

    IpcIoPendingRequest *const pending = new IpcIoPendingRequest(this);
    trackPendingRequest(*pending);
}

void
IpcIoFile::openCompleted(const Ipc::StrandSearchResponse *const response) {
    debugs(0,0,HERE);
    Must(diskId < 0); // we do not know our disker yet
    Must(!workerQueue);

    if (!response) {
        debugs(79,1, HERE << "error: timeout");
        error_ = true;
    } else {
        diskId = response->strand.kidId;
        if (diskId >= 0) {
            workerQueue = DiskerQueue::Attach(dbName.termedBuf(), KidIdentifier);
            ipcIoFiles.insert(std::make_pair(diskId, this));
        } else {
            error_ = true;
            debugs(79,1, HERE << "error: no disker claimed " << dbName);
        }
    }

    ioRequestor->ioCompletedNotification();
}

/**
 * Alias for IpcIoFile::open(...)
 \copydoc IpcIoFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
 */
void
IpcIoFile::create(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    debugs(0,0,HERE);
    assert(false); // check
    /* We use the same logic path for open */
    open(flags, mode, callback);
}

void
IpcIoFile::close()
{
    debugs(0,0,HERE);
    assert(ioRequestor != NULL);

    delete diskerQueue;
    delete workerQueue;

    if (IamDiskProcess())
        DiskerClose(dbName);
    // XXX: else nothing to do?

    ioRequestor->closeCompleted();
}

bool
IpcIoFile::canRead() const
{
    return diskId >= 0;
}

bool
IpcIoFile::canWrite() const
{
    return diskId >= 0;
}

bool
IpcIoFile::error() const
{
    return error_;
}

void
IpcIoFile::read(ReadRequest *readRequest)
{
    debugs(79,3, HERE << "(disker" << diskId << ", " << readRequest->len << ", " <<
        readRequest->offset << ")");

    assert(ioRequestor != NULL);
    assert(readRequest->len >= 0);
    assert(readRequest->offset >= 0);
    Must(!error_);

    //assert(minOffset < 0 || minOffset <= readRequest->offset);
    //assert(maxOffset < 0 || readRequest->offset + readRequest->len <= (uint64_t)maxOffset);

    IpcIoPendingRequest *const pending = new IpcIoPendingRequest(this);
    pending->readRequest = readRequest;
    push(*pending);
}

void
IpcIoFile::readCompleted(ReadRequest *readRequest,
                         const IpcIoMsg *const response)
{
    debugs(0,0,HERE);
    bool ioError = false;
    if (!response) {
        debugs(79,1, HERE << "error: timeout");
        ioError = true; // I/O timeout does not warrant setting error_?
    } else
    if (response->xerrno) {
        debugs(79,1, HERE << "error: " << xstrerr(response->xerrno));
        ioError = error_ = true;
    } else {
        memcpy(readRequest->buf, response->buf, response->len);
    }

    const ssize_t rlen = ioError ? -1 : (ssize_t)readRequest->len;
    const int errflag = ioError ? DISK_ERROR : DISK_OK;
    ioRequestor->readCompleted(readRequest->buf, rlen, errflag, readRequest);
}

void
IpcIoFile::write(WriteRequest *writeRequest)
{
    debugs(79,3, HERE << "(disker" << diskId << ", " << writeRequest->len << ", " <<
        writeRequest->offset << ")");

    assert(ioRequestor != NULL);
    assert(writeRequest->len >= 0);
    assert(writeRequest->len > 0); // TODO: work around mmap failures on zero-len?
    assert(writeRequest->offset >= 0);
    Must(!error_);

    //assert(minOffset < 0 || minOffset <= writeRequest->offset);
    //assert(maxOffset < 0 || writeRequest->offset + writeRequest->len <= (uint64_t)maxOffset);

    IpcIoPendingRequest *const pending = new IpcIoPendingRequest(this);
    pending->writeRequest = writeRequest;
    push(*pending);
}

void
IpcIoFile::writeCompleted(WriteRequest *writeRequest,
                          const IpcIoMsg *const response)
{
    debugs(0,0,HERE);
    bool ioError = false;
    if (!response) {
        debugs(79,1, HERE << "error: timeout");
        ioError = true; // I/O timeout does not warrant setting error_?
    } else
    if (response->xerrno) {
        debugs(79,1, HERE << "error: " << xstrerr(response->xerrno));
        ioError = error_ = true;
    } else
    if (response->len != writeRequest->len) {
        debugs(79,1, HERE << "problem: " << response->len << " < " << writeRequest->len);
        error_ = true;
    }

    if (writeRequest->free_func)
        (writeRequest->free_func)(const_cast<char*>(writeRequest->buf)); // broken API?

    if (!ioError) {
        debugs(79,5, HERE << "wrote " << writeRequest->len << " to disker" <<
            diskId << " at " << writeRequest->offset);
	}

    const ssize_t rlen = ioError ? 0 : (ssize_t)writeRequest->len;
    const int errflag = ioError ? DISK_ERROR : DISK_OK;
    ioRequestor->writeCompleted(errflag, rlen, writeRequest);
}

bool
IpcIoFile::ioInProgress() const
{
    return !olderRequests->empty() || !newerRequests->empty();
}

/// track a new pending request
void
IpcIoFile::trackPendingRequest(IpcIoPendingRequest &pending)
{
    debugs(0,0,HERE);
    newerRequests->insert(std::make_pair(pending.id, &pending));
    if (!timeoutCheckScheduled)
        scheduleTimeoutCheck();
}

/// push an I/O request to disker
void
IpcIoFile::push(IpcIoPendingRequest &pending)
{
    debugs(0,0,HERE);
    Must(diskId >= 0);
    Must(workerQueue);
    Must(pending.readRequest || pending.writeRequest);

    IpcIoMsg ipcIo;
    if (pending.readRequest) {
        ipcIo.command = IpcIo::cmdRead;
        ipcIo.offset = pending.readRequest->offset;
        ipcIo.len = pending.readRequest->len;
        assert(ipcIo.len <= sizeof(ipcIo.buf));
        memcpy(ipcIo.buf, pending.readRequest->buf, ipcIo.len); // optimize away
    } else { // pending.writeRequest
        ipcIo.command = IpcIo::cmdWrite;
        ipcIo.offset = pending.writeRequest->offset;
        ipcIo.len = pending.writeRequest->len;
        assert(ipcIo.len <= sizeof(ipcIo.buf));
        memcpy(ipcIo.buf, pending.writeRequest->buf, ipcIo.len); // optimize away
    }

    if (!workerQueue->push(ipcIo)) {
        pending.completeIo(NULL);
        return;
    }

    if (workerQueue->pushedSize() == 1)
        Notify(diskId); // notify disker

    trackPendingRequest(pending);
}

/// called when coordinator responds to worker open request
void
IpcIoFile::HandleOpenResponse(const Ipc::StrandSearchResponse &response)
{
    debugs(47, 7, HERE << "coordinator response to open request");
    Must(response.data);
    reinterpret_cast<IpcIoFile*>(response.data)->openCompleted(&response);
}

void
IpcIoFile::handleResponses()
{
    Must(workerQueue);
    IpcIoMsg ipcIo;
    while (workerQueue->pop(ipcIo))
        handleResponse(ipcIo);
}

void
IpcIoFile::handleResponse(const IpcIoMsg &ipcIo)
{
    const int requestId = ipcIo.requestId;
    debugs(47, 7, HERE << "disker response to " << ipcIo.command <<
           "; ipcIo" << KidIdentifier << '.' << requestId);
    Must(requestId);
    if (IpcIoPendingRequest *const pending = dequeueRequest(requestId)) {
        pending->completeIo(&ipcIo);
        delete pending; // XXX: leaking if throwing
    } else {
        debugs(47, 4, HERE << "LATE disker response to " << ipcIo.command <<
               "; ipcIo" << KidIdentifier << '.' << requestId);
        // nothing we can do about it; completeIo() has been called already
    }
}

void
IpcIoFile::Notify(const int peerId)
{
    debugs(0,0,HERE);
    Ipc::TypedMsgHdr msg;
    msg.setType(Ipc::mtIpcIoNotification); // TODO: add proper message type?
    msg.putInt(KidIdentifier);
    const String addr = Ipc::Port::MakeAddr(Ipc::strandAddrPfx, peerId);
    Ipc::SendMessage(addr, msg);
}

void
IpcIoFile::HandleNotification(const Ipc::TypedMsgHdr &msg)
{
    debugs(0,0,HERE);
    if (IamDiskProcess())
        DiskerHandleRequests();
    else {
        const int diskId = msg.getInt();
        const IpcIoFiles::const_iterator i = ipcIoFiles.find(diskId);
        Must(i != ipcIoFiles.end()); // XXX: warn and continue?
        i->second->handleResponses();
    }
}

/// IpcIoFile::checkTimeouts wrapper
void
IpcIoFile::CheckTimeouts(void *const param)
{
    debugs(0,0,HERE);
    Must(param);
    reinterpret_cast<IpcIoFile*>(param)->checkTimeouts();
}

void
IpcIoFile::checkTimeouts()
{
    debugs(0,0,HERE);
    timeoutCheckScheduled = false;

    // any old request would have timed out by now
    typedef RequestMap::const_iterator RMCI;
    for (RMCI i = olderRequests->begin(); i != olderRequests->end(); ++i) {
        IpcIoPendingRequest *const pending = i->second;

        const int requestId = i->first;
        debugs(47, 7, HERE << "disker timeout; ipcIo" <<
               KidIdentifier << '.' << diskId << '.' << requestId);

        pending->completeIo(NULL); // no response
        delete pending; // XXX: leaking if throwing
    }
    olderRequests->clear();

    swap(olderRequests, newerRequests); // switches pointers around
    if (!olderRequests->empty())
        scheduleTimeoutCheck();
}

/// prepare to check for timeouts in a little while
void
IpcIoFile::scheduleTimeoutCheck()
{
    debugs(0,0,HERE);
    // we check all older requests at once so some may be wait for 2*timeout
    const double timeout = 7; // in seconds
    eventAdd("IpcIoFile::CheckTimeouts", &IpcIoFile::CheckTimeouts,
             this, timeout, 0, false);
    timeoutCheckScheduled = true;
}

/// returns and forgets the right IpcIoFile pending request
IpcIoPendingRequest *
IpcIoFile::dequeueRequest(const unsigned int requestId)
{
    debugs(47, 3, HERE);
    Must(requestId != 0);

    RequestMap *map = NULL;
    RequestMap::iterator i = requestMap1.find(requestId);

    if (i != requestMap1.end())
        map = &requestMap1;
    else {
        i = requestMap2.find(requestId);
        if (i != requestMap2.end())
            map = &requestMap2;
    }

    if (!map) // not found in both maps
        return NULL;

    IpcIoPendingRequest *pending = i->second;
    map->erase(i);
    return pending;
}

int
IpcIoFile::getFD() const
{
    assert(false); // not supported; TODO: remove this method from API
    return -1;
}


/* IpcIoMsg */

IpcIoMsg::IpcIoMsg():
    requestId(0), offset(0), len(0), command(IpcIo::cmdNone), xerrno(0)
{
}

/* IpcIoPendingRequest */

IpcIoPendingRequest::IpcIoPendingRequest(const IpcIoFile::Pointer &aFile):
    file(aFile), readRequest(NULL), writeRequest(NULL)
{
    debugs(0,0,HERE);
    if (++file->lastRequestId == 0) // don't use zero value as requestId
        ++file->lastRequestId;
    id = file->lastRequestId;
}

void
IpcIoPendingRequest::completeIo(const IpcIoMsg *const response)
{
    debugs(0,0,HERE);
    Must(file != NULL);

    if (readRequest)
        file->readCompleted(readRequest, response);
    else
    if (writeRequest)
        file->writeCompleted(writeRequest, response);
    else {
        Must(!response); // only timeouts are handled here
        file->openCompleted(NULL);
    }
}



/* XXX: disker code that should probably be moved elsewhere */

static int TheFile = -1; ///< db file descriptor

static void
diskerRead(IpcIoMsg &ipcIo)
{
    debugs(0,0,HERE);
    const ssize_t read = pread(TheFile, ipcIo.buf, ipcIo.len, ipcIo.offset);
    statCounter.syscalls.disk.reads++;
    fd_bytes(TheFile, read, FD_READ);

    if (read >= 0) {
        ipcIo.xerrno = 0;
        const size_t len = static_cast<size_t>(read); // safe because read > 0
        debugs(47,8, HERE << "disker" << KidIdentifier << " read " <<
            (len == ipcIo.len ? "all " : "just ") << read);
        ipcIo.len = len;
    } else {
        ipcIo.xerrno = errno;
        ipcIo.len = 0;
        debugs(47,5, HERE << "disker" << KidIdentifier << " read error: " <<
            ipcIo.xerrno);
    }
}

static void
diskerWrite(IpcIoMsg &ipcIo)
{
    debugs(0,0,HERE);
    const ssize_t wrote = pwrite(TheFile, ipcIo.buf, ipcIo.len, ipcIo.offset);
    statCounter.syscalls.disk.writes++;
    fd_bytes(TheFile, wrote, FD_WRITE);

    if (wrote >= 0) {
        ipcIo.xerrno = 0;
        const size_t len = static_cast<size_t>(wrote); // safe because wrote > 0
        debugs(47,8, HERE << "disker" << KidIdentifier << " wrote " <<
            (len == ipcIo.len ? "all " : "just ") << wrote);
        ipcIo.len = len;
    } else {
        ipcIo.xerrno = errno;
        ipcIo.len = 0;
        debugs(47,5, HERE << "disker" << KidIdentifier << " write error: " <<
               ipcIo.xerrno);
    }
}

void
IpcIoFile::DiskerHandleRequests()
{
    debugs(0,0,HERE);
    Must(diskerQueue);
    int workerId;
    IpcIoMsg ipcIo;
    while (diskerQueue->pop(workerId, ipcIo))
        DiskerHandleRequest(workerId, ipcIo);
}

/// called when disker receives an I/O request
void
IpcIoFile::DiskerHandleRequest(const int workerId, IpcIoMsg &ipcIo)
{
    debugs(0,0,HERE);
    Must(diskerQueue);

    if (ipcIo.command != IpcIo::cmdRead && ipcIo.command != IpcIo::cmdWrite) {
        debugs(0,0, HERE << "disker" << KidIdentifier <<
               " should not receive " << ipcIo.command <<
               " ipcIo" << workerId << '.' << ipcIo.requestId);
        return;
    }

    debugs(47,5, HERE << "disker" << KidIdentifier <<
           (ipcIo.command == IpcIo::cmdRead ? " reads " : " writes ") <<
           ipcIo.len << " at " << ipcIo.offset <<
           " ipcIo" << workerId << '.' << ipcIo.requestId);

    if (ipcIo.command == IpcIo::cmdRead)
        diskerRead(ipcIo);
    else // ipcIo.command == IpcIo::cmdWrite
        diskerWrite(ipcIo);

    diskerQueue->push(workerId, ipcIo); // XXX: report warning

    if (diskerQueue->pushedSize(workerId) == 1)
        Notify(workerId); // notify worker
}

static bool
DiskerOpen(const String &path, int flags, mode_t mode)
{
    debugs(0,0,HERE);
    assert(TheFile < 0);

    TheFile = file_open(path.termedBuf(), flags);

    if (TheFile < 0) {
        const int xerrno = errno;
        debugs(47,0, HERE << "rock db error opening " << path << ": " <<
               xstrerr(xerrno));
        return false;
    }

    store_open_disk_fd++;
    debugs(79,3, HERE << "rock db opened " << path << ": FD " << TheFile);
    return true;
}

static void
DiskerClose(const String &path)
{
    debugs(0,0,HERE);
    if (TheFile >= 0) {
        file_close(TheFile);
        debugs(79,3, HERE << "rock db closed " << path << ": FD " << TheFile);
        TheFile = -1;
        store_open_disk_fd--;
	}
}
