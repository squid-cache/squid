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
#include "ipc/StrandCoord.h"
#include "ipc/UdsOp.h"

CBDATA_CLASS_INIT(IpcIoFile);

IpcIoFile::RequestsMap IpcIoFile::TheRequestsMap;
unsigned int IpcIoFile::LastRequestId = 0;

static bool DiskerOpen(const String &path, int flags, mode_t mode);
static void DiskerClose(const String &path);


IpcIoFile::IpcIoFile(char const *aDb):
    dbName(aDb),
    diskId(-1),
    ioLevel(0),
    error_(false)
{
}

IpcIoFile::~IpcIoFile()
{
}

void
IpcIoFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    ioRequestor = callback;
    Must(diskId < 0); // we do not know our disker yet

    if (IamDiskProcess()) {
        error_ = !DiskerOpen(dbName, flags, mode);
        if (error_)
            return;

        ioRequestor->ioCompletedNotification();

        Ipc::HereIamMessage ann(Ipc::StrandCoord(KidIdentifier, getpid()));
        ann.strand.tag = dbName;
        Ipc::TypedMsgHdr message;
        ann.pack(message);
        SendMessage(Ipc::coordinatorAddr, message);

        return;
	}        

    // XXX: use StrandSearchRequest instead
    IpcIoRequest ipcIo;
    ipcIo.requestorId = KidIdentifier;
    ipcIo.command = IpcIo::cmdOpen;
    ipcIo.len = dbName.size();
    assert(ipcIo.len <= sizeof(ipcIo.buf));
    memcpy(ipcIo.buf, dbName.rawBuf(), ipcIo.len);    

    IpcIoPendingRequest *pending = new IpcIoPendingRequest(this);
    send(ipcIo, pending);
}

void
IpcIoFile::openCompleted(const IpcIoResponse &ipcResponse) {
    if (ipcResponse.xerrno) {
        debugs(79,1, HERE << "error: " << xstrerr(ipcResponse.xerrno));
        error_ = true;
	} else {
        diskId = ipcResponse.diskId;
        if (diskId < 0) {
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
    assert(false); // check
    /* We use the same logic path for open */
    open(flags, mode, callback);
}

void
IpcIoFile::close()
{
    assert(ioRequestor != NULL);

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

    IpcIoRequest ipcIo;
    ipcIo.requestorId = KidIdentifier;
    ipcIo.command = IpcIo::cmdRead;
    ipcIo.offset = readRequest->offset;
    ipcIo.len = readRequest->len;

    IpcIoPendingRequest *pending = new IpcIoPendingRequest(this);
    pending->readRequest = readRequest;
    send(ipcIo, pending);
}

void
IpcIoFile::readCompleted(ReadRequest *readRequest,
                         const IpcIoResponse &ipcResponse)
{
    if (ipcResponse.xerrno) {
        debugs(79,1, HERE << "error: " << xstrerr(ipcResponse.xerrno));
        error_ = true;
	}

    const ssize_t rlen = error_ ? -1 : (ssize_t)readRequest->len;
    const int errflag = error_ ? DISK_ERROR : DISK_OK;
    // XXX: check buffering expectations of the recepient
    ioRequestor->readCompleted(ipcResponse.buf, rlen, errflag, readRequest);
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

    IpcIoRequest ipcIo;
    ipcIo.requestorId = KidIdentifier;
    ipcIo.command = IpcIo::cmdWrite;
    ipcIo.offset = writeRequest->offset;
    ipcIo.len = writeRequest->len;
    assert(ipcIo.len <= sizeof(ipcIo.buf));
    memcpy(ipcIo.buf, writeRequest->buf, ipcIo.len); // optimize away

    IpcIoPendingRequest *pending = new IpcIoPendingRequest(this);
    pending->writeRequest = writeRequest;
    send(ipcIo, pending);
}

void
IpcIoFile::writeCompleted(WriteRequest *writeRequest,
                          const IpcIoResponse &ipcResponse)
{
    if (ipcResponse.xerrno) {
        debugs(79,1, HERE << "error: " << xstrerr(ipcResponse.xerrno));
        error_ = true;
    } else
    if (ipcResponse.len != writeRequest->len) {
        debugs(79,1, HERE << "problem: " << ipcResponse.len << " < " << writeRequest->len);
        error_ = true;
    }

    if (writeRequest->free_func)
        (writeRequest->free_func)(const_cast<char*>(writeRequest->buf)); // broken API?

    if (!error_) {
        debugs(79,5, HERE << "wrote " << writeRequest->len << " to disker" <<
            diskId << " at " << writeRequest->offset);
	}

    const ssize_t rlen = error_ ? 0 : (ssize_t)writeRequest->len;
    const int errflag = error_ ? DISK_ERROR : DISK_OK;
    ioRequestor->writeCompleted(errflag, rlen, writeRequest);
}

bool
IpcIoFile::ioInProgress() const
{
    return ioLevel > 0; // XXX: todo
}

/// sends an I/O request to disker
void
IpcIoFile::send(IpcIoRequest &ipcIo, IpcIoPendingRequest *pending)
{
    if (++LastRequestId == 0) // don't use zero value as requestId
        ++LastRequestId;
    ipcIo.requestId = LastRequestId;
    TheRequestsMap[ipcIo.requestId] = pending;

    Ipc::TypedMsgHdr message;
    ipcIo.pack(message);

    Must(diskId >= 0 || ipcIo.command == IpcIo::cmdOpen);
    const String addr = diskId >= 0 ?
        Ipc::Port::MakeAddr(Ipc::strandAddrPfx, diskId) :
        Ipc::coordinatorAddr;

    debugs(47, 7, HERE << "asking disker" << diskId << " to " <<
        ipcIo.command << "; ipcIo" << KidIdentifier << '.' << ipcIo.requestId);

    Ipc::SendMessage(addr, message);
    ++ioLevel;

    const double timeout = 10; // in seconds
    eventAdd("IpcIoFile::requestTimedOut", &IpcIoFile::RequestTimedOut,
             this, timeout, 0, false);
}

/// called when disker responds to our I/O request
void
IpcIoFile::HandleResponse(const Ipc::TypedMsgHdr &raw)
{
    IpcIoResponse response(raw);

    const int requestId = response.requestId;
    debugs(47, 7, HERE << "disker response to " <<
        response.command << "; ipcIo" << KidIdentifier << '.' << requestId);

    Must(requestId != 0);

    IpcIoPendingRequest *pending = DequeueRequest(requestId);
    Must(pending);

    if (pending->readRequest)
        pending->file->readCompleted(pending->readRequest, response);
    else
    if (pending->writeRequest)
        pending->file->writeCompleted(pending->writeRequest, response);
    else
        pending->file->openCompleted(response);

    // XXX: leaking if throwinig
    delete pending;
}


/// Mgr::IpcIoFile::requestTimedOut wrapper
void
IpcIoFile::RequestTimedOut(void* param)
{
    debugs(47, 1, HERE << "bug: request timedout and we cannot handle that");
    Must(param != NULL);
    // XXX: cannot get to file because IpcIoFile is not cbdata-protected
    // IpcIoFile* file = static_cast<IpcIoFile*>(param);

    // TODO: notify the pending request (XXX: which one?)

    // use async call to enable job call protection that time events lack
    // CallJobHere(47, 5, mgrFwdr, IpcIoFile, requestTimedOut);
}

/// Called when Coordinator fails to start processing the request [in time]
void
IpcIoFile::requestTimedOut()
{
    debugs(47, 3, HERE);
    assert(false); // TODO: notify the pending request (XXX: which one?)
}

/// called when we are no longer waiting for Coordinator to respond
void
IpcIoFile::removeTimeoutEvent()
{
    if (eventFind(&IpcIoFile::RequestTimedOut, this))
        eventDelete(&IpcIoFile::RequestTimedOut, this);
}

/// returns and forgets the right IpcIoFile pending request
IpcIoPendingRequest *
IpcIoFile::DequeueRequest(unsigned int requestId)
{
    debugs(47, 3, HERE);
    Must(requestId != 0);
    RequestsMap::iterator i = TheRequestsMap.find(requestId);
    if (i != TheRequestsMap.end()) {
        IpcIoPendingRequest *pending = i->second;
        TheRequestsMap.erase(i);
        return pending;
	}
    return NULL;
}

int
IpcIoFile::getFD() const 
{
    assert(false); // not supported; TODO: remove this method from API
    return -1;
}


/* IpcIoRequest */

IpcIoRequest::IpcIoRequest():
    requestorId(0), requestId(0),
    offset(0), len(0),
    command(IpcIo::cmdNone)
{
}

IpcIoRequest::IpcIoRequest(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtIpcIoRequest);
    msg.getPod(requestorId);
    msg.getPod(requestId);
   
    msg.getPod(offset);
    msg.getPod(len);
    msg.getPod(command);

    if (command == IpcIo::cmdOpen || command == IpcIo::cmdWrite)
        msg.getFixed(buf, len);
}

void
IpcIoRequest::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtIpcIoRequest);
    msg.putPod(requestorId);
    msg.putPod(requestId);

    msg.putPod(offset);
    msg.putPod(len);
    msg.putPod(command);

    if (command == IpcIo::cmdOpen || command == IpcIo::cmdWrite)
        msg.putFixed(buf, len);
}


/* IpcIoResponse */

IpcIoResponse::IpcIoResponse():
    diskId(-1),
    requestId(0),
    len(0),
    xerrno(0)
{
}

IpcIoResponse::IpcIoResponse(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtIpcIoResponse);
    msg.getPod(diskId);
    msg.getPod(requestId);
    msg.getPod(len);
    msg.getPod(command);
    msg.getPod(xerrno);

    if (command == IpcIo::cmdRead && !xerrno)
        msg.getFixed(buf, len);
}

void
IpcIoResponse::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtIpcIoResponse);
    msg.putPod(diskId);
    msg.putPod(requestId);
    msg.putPod(len);
    msg.putPod(command);
    msg.putPod(xerrno);

    if (command == IpcIo::cmdRead && !xerrno)
        msg.putFixed(buf, len);
}


/* IpcIoPendingRequest: */

IpcIoPendingRequest::IpcIoPendingRequest(const IpcIoFile::Pointer &aFile):
    file(aFile), readRequest(NULL), writeRequest(NULL)
{
}


/* XXX: disker code that should probably be moved elsewhere */

static int TheFile = -1; ///< db file descriptor

static
void diskerRead(const IpcIoRequest &request)
{
    debugs(47,5, HERE << "disker" << KidIdentifier << " reads " <<
        request.len << " at " << request.offset <<
        " ipcIo" << request.requestorId << '.' << request.requestId);

    IpcIoResponse response;
    response.diskId = KidIdentifier;
    response.requestId = request.requestId;
    response.command = request.command;

    const ssize_t read = pread(TheFile, response.buf, request.len, request.offset);
    if (read >= 0) {
        response.xerrno = 0;
        response.len = static_cast<size_t>(read); // safe because read > 0
        debugs(47,8, HERE << "disker" << KidIdentifier << " read " <<
            (response.len == request.len ? "all " : "just ") << read);
	} else {
        response.xerrno = errno;
        response.len = 0;
        debugs(47,5, HERE << "disker" << KidIdentifier << " read error: " <<
            response.xerrno);
	}
    
    Ipc::TypedMsgHdr message;
    response.pack(message);
    const String addr =
        Ipc::Port::MakeAddr(Ipc::strandAddrPfx, request.requestorId);
    Ipc::SendMessage(addr, message);
}

static
void diskerWrite(const IpcIoRequest &request)
{
    debugs(47,5, HERE << "disker" << KidIdentifier << " writes " <<
        request.len << " at " << request.offset <<
        " ipcIo" << request.requestorId << '.' << request.requestId);

    IpcIoResponse response;
    response.diskId = KidIdentifier;
    response.requestId = request.requestId;
    response.command = request.command;

    const ssize_t wrote = pwrite(TheFile, request.buf, request.len, request.offset);
    if (wrote >= 0) {
        response.xerrno = 0;
        response.len = static_cast<size_t>(wrote); // safe because wrote > 0
        debugs(47,8, HERE << "disker" << KidIdentifier << " wrote " <<
            (response.len == request.len ? "all " : "just ") << wrote);
	} else {
        response.xerrno = errno;
        response.len = 0;
        debugs(47,5, HERE << "disker" << KidIdentifier << " write error: " <<
            response.xerrno);
	}
    
    Ipc::TypedMsgHdr message;
    response.pack(message);
    const String addr =
        Ipc::Port::MakeAddr(Ipc::strandAddrPfx, request.requestorId);
    Ipc::SendMessage(addr, message);
}

/// called when disker receives an I/O request
void
IpcIoFile::HandleRequest(const IpcIoRequest &request)
{
    switch (request.command) {
    case IpcIo::cmdRead:
        diskerRead(request);
        break;

    case IpcIo::cmdWrite:
        diskerWrite(request);
        break;

    default:
        debugs(0,0, HERE << "disker" << KidIdentifier <<
               " should not receive " << request.command <<
               " ipcIo" << request.requestorId << '.' << request.requestId);
        break;
	}
}

static bool
DiskerOpen(const String &path, int flags, mode_t mode)
{
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
    if (TheFile >= 0) {
        file_close(TheFile);
        debugs(79,3, HERE << "rock db closed " << path << ": FD " << TheFile);
        TheFile = -1;
        store_open_disk_fd--;
	}
}
