/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Directory Routines */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "base/TextException.h"
#include "DiskIO/IORequestor.h"
#include "DiskIO/IpcIo/IpcIoFile.h"
#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fd.h"
#include "fs_io.h"
#include "globals.h"
#include "ipc/mem/Pages.h"
#include "ipc/Messages.h"
#include "ipc/Port.h"
#include "ipc/Queue.h"
#include "ipc/StrandSearch.h"
#include "ipc/UdsOp.h"
#include "sbuf/SBuf.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "tools.h"

#include <cerrno>

CBDATA_CLASS_INIT(IpcIoFile);

/// shared memory segment path to use for IpcIoFile maps
static const char *const ShmLabel = "io_file";
/// a single worker-to-disker or disker-to-worker queue capacity; up
/// to 2*QueueCapacity I/O requests queued between a single worker and
/// a single disker
// TODO: make configurable or compute from squid.conf settings if possible
static const int QueueCapacity = 1024;

const double IpcIoFile::Timeout = 7; // seconds;  XXX: ALL,9 may require more
IpcIoFile::IpcIoFileList IpcIoFile::WaitingForOpen;
IpcIoFile::IpcIoFilesMap IpcIoFile::IpcIoFiles;
std::unique_ptr<IpcIoFile::Queue> IpcIoFile::queue;

bool IpcIoFile::DiskerHandleMoreRequestsScheduled = false;

static bool DiskerOpen(const SBuf &path, int flags, mode_t mode);
static void DiskerClose(const SBuf &path);

/// IpcIo wrapper for debugs() streams; XXX: find a better class name
struct SipcIo {
    SipcIo(int aWorker, const IpcIoMsg &aMsg, int aDisker):
        worker(aWorker), msg(aMsg), disker(aDisker) {}

    int worker;
    const IpcIoMsg &msg;
    int disker;
};

std::ostream &
operator <<(std::ostream &os, const SipcIo &sio)
{
    return os << "ipcIo" << sio.worker << '.' << sio.msg.requestId <<
           (sio.msg.command == IpcIo::cmdRead ? 'r' : 'w') << sio.disker;
}

IpcIoFile::IpcIoFile(char const *aDb):
    dbName(aDb), diskId(-1), error_(false), lastRequestId(0),
    olderRequests(&requestMap1), newerRequests(&requestMap2),
    timeoutCheckScheduled(false)
{
}

IpcIoFile::~IpcIoFile()
{
    SWALLOW_EXCEPTIONS({
        if (diskId >= 0) {
            const auto i = IpcIoFiles.find(diskId);
            Must(i != IpcIoFiles.end());
            Must(i->second == this);
            IpcIoFiles.erase(i);
        }
    });
}

void
IpcIoFile::configure(const Config &cfg)
{
    DiskFile::configure(cfg);
    config = cfg;
}

void
IpcIoFile::open(int flags, mode_t mode, RefCount<IORequestor> callback)
{
    ioRequestor = callback;
    Must(diskId < 0); // we do not know our disker yet

    if (!queue.get())
        queue.reset(new Queue(ShmLabel, IamWorkerProcess() ? Queue::groupA : Queue::groupB, KidIdentifier));

    if (IamDiskProcess()) {
        error_ = !DiskerOpen(SBuf(dbName.termedBuf()), flags, mode);
        if (error_)
            return;

        diskId = KidIdentifier;
        const bool inserted =
            IpcIoFiles.insert(std::make_pair(diskId, this)).second;
        Must(inserted);

        queue->localRateLimit().store(config.ioRate);

        Ipc::HereIamMessage ann(Ipc::StrandCoord(KidIdentifier, getpid()));
        ann.strand.tag = dbName;
        Ipc::TypedMsgHdr message;
        ann.pack(message);
        SendMessage(Ipc::Port::CoordinatorAddr(), message);

        ioRequestor->ioCompletedNotification();
        return;
    }

    Ipc::StrandSearchRequest request;
    request.requestorId = KidIdentifier;
    request.tag = dbName;

    Ipc::TypedMsgHdr msg;
    request.pack(msg);
    Ipc::SendMessage(Ipc::Port::CoordinatorAddr(), msg);

    WaitingForOpen.push_back(this);

    eventAdd("IpcIoFile::OpenTimeout", &IpcIoFile::OpenTimeout,
             this, Timeout, 0, false); // "this" pointer is used as id
}

void
IpcIoFile::openCompleted(const Ipc::StrandSearchResponse *const response)
{
    Must(diskId < 0); // we do not know our disker yet

    if (!response) {
        debugs(79, DBG_IMPORTANT, "ERROR: " << dbName << " communication " <<
               "channel establishment timeout");
        error_ = true;
    } else {
        diskId = response->strand.kidId;
        if (diskId >= 0) {
            const bool inserted =
                IpcIoFiles.insert(std::make_pair(diskId, this)).second;
            Must(inserted);
        } else {
            error_ = true;
            debugs(79, DBG_IMPORTANT, "ERROR: no disker claimed " <<
                   "responsibility for " << dbName);
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
        DiskerClose(SBuf(dbName.termedBuf()));
    // XXX: else nothing to do?

    ioRequestor->closeCompleted();
}

bool
IpcIoFile::canRead() const
{
    return diskId >= 0 && !error_ && canWait();
}

bool
IpcIoFile::canWrite() const
{
    return diskId >= 0 && !error_ && canWait();
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
    assert(readRequest->offset >= 0);
    Must(!error_);

    //assert(minOffset < 0 || minOffset <= readRequest->offset);
    //assert(maxOffset < 0 || readRequest->offset + readRequest->len <= (uint64_t)maxOffset);

    IpcIoPendingRequest *const pending = new IpcIoPendingRequest(this);
    pending->readRequest = readRequest;
    push(pending);
}

void
IpcIoFile::readCompleted(ReadRequest *readRequest,
                         IpcIoMsg *const response)
{
    bool ioError = false;
    if (!response) {
        debugs(79, 3, HERE << "error: timeout");
        ioError = true; // I/O timeout does not warrant setting error_?
    } else {
        if (response->xerrno) {
            debugs(79, DBG_IMPORTANT, "ERROR: " << dbName << " read: " <<
                   xstrerr(response->xerrno));
            ioError = error_ = true;
        } else if (!response->page) {
            debugs(79, DBG_IMPORTANT, "ERROR: " << dbName << " read ran " <<
                   "out of shared memory pages");
            ioError = true;
        } else {
            const char *const buf = Ipc::Mem::PagePointer(response->page);
            memcpy(readRequest->buf, buf, response->len);
        }

        Ipc::Mem::PutPage(response->page);
    }

    const ssize_t rlen = ioError ? -1 : (ssize_t)readRequest->len;
    const int errflag = ioError ? DISK_ERROR :DISK_OK;
    ioRequestor->readCompleted(readRequest->buf, rlen, errflag, readRequest);
}

void
IpcIoFile::write(WriteRequest *writeRequest)
{
    debugs(79,3, HERE << "(disker" << diskId << ", " << writeRequest->len << ", " <<
           writeRequest->offset << ")");

    assert(ioRequestor != NULL);
    assert(writeRequest->len > 0); // TODO: work around mmap failures on zero-len?
    assert(writeRequest->offset >= 0);
    Must(!error_);

    //assert(minOffset < 0 || minOffset <= writeRequest->offset);
    //assert(maxOffset < 0 || writeRequest->offset + writeRequest->len <= (uint64_t)maxOffset);

    IpcIoPendingRequest *const pending = new IpcIoPendingRequest(this);
    pending->writeRequest = writeRequest;
    push(pending);
}

void
IpcIoFile::writeCompleted(WriteRequest *writeRequest,
                          const IpcIoMsg *const response)
{
    bool ioError = false;
    if (!response) {
        debugs(79, 3, "disker " << diskId << " timeout");
        ioError = true; // I/O timeout does not warrant setting error_?
    } else if (response->xerrno) {
        debugs(79, DBG_IMPORTANT, "ERROR: disker " << diskId <<
               " error writing " << writeRequest->len << " bytes at " <<
               writeRequest->offset << ": " << xstrerr(response->xerrno) <<
               "; this worker will stop using " << dbName);
        ioError = error_ = true;
    } else if (response->len != writeRequest->len) {
        debugs(79, DBG_IMPORTANT, "ERROR: disker " << diskId << " wrote " <<
               response->len << " instead of " << writeRequest->len <<
               " bytes (offset " << writeRequest->offset << "); " <<
               "this worker will stop using " << dbName);
        error_ = true;
    }

    if (writeRequest->free_func)
        (writeRequest->free_func)(const_cast<char*>(writeRequest->buf)); // broken API?

    if (!ioError) {
        debugs(79,5, HERE << "wrote " << writeRequest->len << " to disker" <<
               diskId << " at " << writeRequest->offset);
    }

    const ssize_t rlen = ioError ? 0 : (ssize_t)writeRequest->len;
    const int errflag = ioError ? DISK_ERROR :DISK_OK;
    ioRequestor->writeCompleted(errflag, rlen, writeRequest);
}

bool
IpcIoFile::ioInProgress() const
{
    return !olderRequests->empty() || !newerRequests->empty();
}

/// track a new pending request
void
IpcIoFile::trackPendingRequest(const unsigned int id, IpcIoPendingRequest *const pending)
{
    const std::pair<RequestMap::iterator,bool> result =
        newerRequests->insert(std::make_pair(id, pending));
    Must(result.second); // failures means that id was not unique
    if (!timeoutCheckScheduled)
        scheduleTimeoutCheck();
}

/// push an I/O request to disker
void
IpcIoFile::push(IpcIoPendingRequest *const pending)
{
    // prevent queue overflows: check for responses to earlier requests
    // warning: this call may result in indirect push() recursion
    HandleResponses("before push");

    debugs(47, 7, HERE);
    Must(diskId >= 0);
    Must(pending);
    Must(pending->readRequest || pending->writeRequest);

    IpcIoMsg ipcIo;
    try {
        if (++lastRequestId == 0) // don't use zero value as requestId
            ++lastRequestId;
        ipcIo.requestId = lastRequestId;
        ipcIo.start = current_time;
        if (pending->readRequest) {
            ipcIo.command = IpcIo::cmdRead;
            ipcIo.offset = pending->readRequest->offset;
            ipcIo.len = pending->readRequest->len;
        } else { // pending->writeRequest
            Must(pending->writeRequest->len <= Ipc::Mem::PageSize());
            if (!Ipc::Mem::GetPage(Ipc::Mem::PageId::ioPage, ipcIo.page)) {
                ipcIo.len = 0;
                throw TexcHere("run out of shared memory pages for IPC I/O");
            }
            ipcIo.command = IpcIo::cmdWrite;
            ipcIo.offset = pending->writeRequest->offset;
            ipcIo.len = pending->writeRequest->len;
            char *const buf = Ipc::Mem::PagePointer(ipcIo.page);
            memcpy(buf, pending->writeRequest->buf, ipcIo.len); // optimize away
        }

        debugs(47, 7, HERE << "pushing " << SipcIo(KidIdentifier, ipcIo, diskId));

        if (queue->push(diskId, ipcIo))
            Notify(diskId); // must notify disker
        trackPendingRequest(ipcIo.requestId, pending);
    } catch (const Queue::Full &) {
        debugs(47, DBG_IMPORTANT, "ERROR: worker I/O push queue for " <<
               dbName << " overflow: " <<
               SipcIo(KidIdentifier, ipcIo, diskId)); // TODO: report queue len
        // TODO: grow queue size

        pending->completeIo(NULL);
        delete pending;
    } catch (const TextException &e) {
        debugs(47, DBG_IMPORTANT, "ERROR: " << dbName << " exception: " << e.what());
        pending->completeIo(NULL);
        delete pending;
    }
}

/// whether we think there is enough time to complete the I/O
bool
IpcIoFile::canWait() const
{
    if (!config.ioTimeout)
        return true; // no timeout specified

    IpcIoMsg oldestIo;
    if (!queue->findOldest(diskId, oldestIo) || oldestIo.start.tv_sec <= 0)
        return true; // we cannot estimate expected wait time; assume it is OK

    const int oldestWait = tvSubMsec(oldestIo.start, current_time);

    int rateWait = -1; // time in millisecons
    const int ioRate = queue->rateLimit(diskId).load();
    if (ioRate > 0) {
        // if there are N requests pending, the new one will wait at
        // least N/max-swap-rate seconds
        rateWait = static_cast<int>(1e3 * queue->outSize(diskId) / ioRate);
        // adjust N/max-swap-rate value based on the queue "balance"
        // member, in case we have been borrowing time against future
        // I/O already
        rateWait += queue->balance(diskId);
    }

    const int expectedWait = max(oldestWait, rateWait);
    if (expectedWait < 0 ||
            static_cast<time_msec_t>(expectedWait) < config.ioTimeout)
        return true; // expected wait time is acceptible

    debugs(47,2, HERE << "cannot wait: " << expectedWait <<
           " oldest: " << SipcIo(KidIdentifier, oldestIo, diskId));
    return false; // do not want to wait that long
}

/// called when coordinator responds to worker open request
void
IpcIoFile::HandleOpenResponse(const Ipc::StrandSearchResponse &response)
{
    debugs(47, 7, HERE << "coordinator response to open request");
    for (IpcIoFileList::iterator i = WaitingForOpen.begin();
            i != WaitingForOpen.end(); ++i) {
        if (response.strand.tag == (*i)->dbName) {
            (*i)->openCompleted(&response);
            WaitingForOpen.erase(i);
            return;
        }
    }

    debugs(47, 4, HERE << "LATE disker response to open for " <<
           response.strand.tag);
    // nothing we can do about it; completeIo() has been called already
}

void
IpcIoFile::HandleResponses(const char *const when)
{
    debugs(47, 4, HERE << "popping all " << when);
    IpcIoMsg ipcIo;
    // get all responses we can: since we are not pushing, this will stop
    int diskId;
    while (queue->pop(diskId, ipcIo)) {
        const IpcIoFilesMap::const_iterator i = IpcIoFiles.find(diskId);
        Must(i != IpcIoFiles.end()); // TODO: warn but continue
        i->second->handleResponse(ipcIo);
    }
}

void
IpcIoFile::handleResponse(IpcIoMsg &ipcIo)
{
    const int requestId = ipcIo.requestId;
    debugs(47, 7, HERE << "popped disker response: " <<
           SipcIo(KidIdentifier, ipcIo, diskId));

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
    // TODO: Count and report the total number of notifications, pops, pushes.
    debugs(47, 7, HERE << "kid" << peerId);
    Ipc::TypedMsgHdr msg;
    msg.setType(Ipc::mtIpcIoNotification); // TODO: add proper message type?
    msg.putInt(KidIdentifier);
    const String addr = Ipc::Port::MakeAddr(Ipc::strandAddrLabel, peerId);
    Ipc::SendMessage(addr, msg);
}

void
IpcIoFile::HandleNotification(const Ipc::TypedMsgHdr &msg)
{
    const int from = msg.getInt();
    debugs(47, 7, HERE << "from " << from);
    queue->clearReaderSignal(from);
    if (IamDiskProcess())
        DiskerHandleRequests();
    else
        HandleResponses("after notification");
}

/// handles open request timeout
void
IpcIoFile::OpenTimeout(void *const param)
{
    Must(param);
    // the pointer is used for comparison only and not dereferenced
    const IpcIoFile *const ipcIoFile =
        reinterpret_cast<const IpcIoFile *>(param);
    for (IpcIoFileList::iterator i = WaitingForOpen.begin();
            i != WaitingForOpen.end(); ++i) {
        if (*i == ipcIoFile) {
            (*i)->openCompleted(NULL);
            WaitingForOpen.erase(i);
            break;
        }
    }
}

/// IpcIoFile::checkTimeouts wrapper
void
IpcIoFile::CheckTimeouts(void *const param)
{
    Must(param);
    const int diskId = reinterpret_cast<uintptr_t>(param);
    debugs(47, 7, HERE << "diskId=" << diskId);
    const IpcIoFilesMap::const_iterator i = IpcIoFiles.find(diskId);
    if (i != IpcIoFiles.end())
        i->second->checkTimeouts();
}

void
IpcIoFile::checkTimeouts()
{
    timeoutCheckScheduled = false;

    // last chance to recover in case a notification message was lost, etc.
    const RequestMap::size_type timeoutsBefore = olderRequests->size();
    HandleResponses("before timeout");
    const RequestMap::size_type timeoutsNow = olderRequests->size();

    if (timeoutsBefore > timeoutsNow) { // some requests were rescued
        // notification message lost or significantly delayed?
        debugs(47, DBG_IMPORTANT, "WARNING: communication with " << dbName <<
               " may be too slow or disrupted for about " <<
               Timeout << "s; rescued " << (timeoutsBefore - timeoutsNow) <<
               " out of " << timeoutsBefore << " I/Os");
    }

    if (timeoutsNow) {
        debugs(47, DBG_IMPORTANT, "WARNING: abandoning " <<
               timeoutsNow << ' ' << dbName << " I/Os after at least " <<
               Timeout << "s timeout");
    }

    // any old request would have timed out by now
    typedef RequestMap::const_iterator RMCI;
    for (RMCI i = olderRequests->begin(); i != olderRequests->end(); ++i) {
        IpcIoPendingRequest *const pending = i->second;

        const unsigned int requestId = i->first;
        debugs(47, 7, HERE << "disker timeout; ipcIo" <<
               KidIdentifier << '.' << requestId);

        pending->completeIo(NULL); // no response
        delete pending; // XXX: leaking if throwing
    }
    olderRequests->clear();

    swap(olderRequests, newerRequests); // switches pointers around
    if (!olderRequests->empty() && !timeoutCheckScheduled)
        scheduleTimeoutCheck();
}

/// prepare to check for timeouts in a little while
void
IpcIoFile::scheduleTimeoutCheck()
{
    // we check all older requests at once so some may be wait for 2*Timeout
    eventAdd("IpcIoFile::CheckTimeouts", &IpcIoFile::CheckTimeouts,
             reinterpret_cast<void *>(diskId), Timeout, 0, false);
    timeoutCheckScheduled = true;
}

/// returns and forgets the right IpcIoFile pending request
IpcIoPendingRequest *
IpcIoFile::dequeueRequest(const unsigned int requestId)
{
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
    requestId(0),
    offset(0),
    len(0),
    command(IpcIo::cmdNone),
    xerrno(0)
{
    start.tv_sec = 0;
    start.tv_usec = 0;
}

/* IpcIoPendingRequest */

IpcIoPendingRequest::IpcIoPendingRequest(const IpcIoFile::Pointer &aFile):
    file(aFile), readRequest(NULL), writeRequest(NULL)
{
}

void
IpcIoPendingRequest::completeIo(IpcIoMsg *const response)
{
    if (readRequest)
        file->readCompleted(readRequest, response);
    else if (writeRequest)
        file->writeCompleted(writeRequest, response);
    else {
        Must(!response); // only timeouts are handled here
        file->openCompleted(NULL);
    }
}

/* XXX: disker code that should probably be moved elsewhere */

static SBuf DbName; ///< full db file name
static int TheFile = -1; ///< db file descriptor

static void
diskerRead(IpcIoMsg &ipcIo)
{
    if (!Ipc::Mem::GetPage(Ipc::Mem::PageId::ioPage, ipcIo.page)) {
        ipcIo.len = 0;
        debugs(47,2, HERE << "run out of shared memory pages for IPC I/O");
        return;
    }

    char *const buf = Ipc::Mem::PagePointer(ipcIo.page);
    const ssize_t read = pread(TheFile, buf, min(ipcIo.len, Ipc::Mem::PageSize()), ipcIo.offset);
    ++statCounter.syscalls.disk.reads;
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

/// Tries to write buffer to disk (a few times if needed);
/// sets ipcIo results, but does no cleanup. The caller must cleanup.
static void
diskerWriteAttempts(IpcIoMsg &ipcIo)
{
    const char *buf = Ipc::Mem::PagePointer(ipcIo.page);
    size_t toWrite = min(ipcIo.len, Ipc::Mem::PageSize());
    size_t wroteSoFar = 0;
    off_t offset = ipcIo.offset;
    // Partial writes to disk do happen. It is unlikely that the caller can
    // handle partial writes by doing something other than writing leftovers
    // again, so we try to write them ourselves to minimize overheads.
    const int attemptLimit = 10;
    for (int attempts = 1; attempts <= attemptLimit; ++attempts) {
        const ssize_t result = pwrite(TheFile, buf, toWrite, offset);
        ++statCounter.syscalls.disk.writes;
        fd_bytes(TheFile, result, FD_WRITE);

        if (result < 0) {
            ipcIo.xerrno = errno;
            assert(ipcIo.xerrno);
            debugs(47, DBG_IMPORTANT, "ERROR: " << DbName << " failure" <<
                   " writing " << toWrite << '/' << ipcIo.len <<
                   " at " << ipcIo.offset << '+' << wroteSoFar <<
                   " on " << attempts << " try: " << xstrerr(ipcIo.xerrno));
            ipcIo.len = wroteSoFar;
            return; // bail on error
        }

        const size_t wroteNow = static_cast<size_t>(result); // result >= 0
        ipcIo.xerrno = 0;

        debugs(47,3, "disker" << KidIdentifier << " wrote " <<
               (wroteNow >= toWrite ? "all " : "just ") << wroteNow <<
               " out of " << toWrite << '/' << ipcIo.len << " at " <<
               ipcIo.offset << '+' << wroteSoFar << " on " << attempts <<
               " try");

        wroteSoFar += wroteNow;

        if (wroteNow >= toWrite) {
            ipcIo.xerrno = 0;
            ipcIo.len = wroteSoFar;
            return; // wrote everything there was to write
        }

        buf += wroteNow;
        offset += wroteNow;
        toWrite -= wroteNow;
    }

    debugs(47, DBG_IMPORTANT, "ERROR: " << DbName << " exhausted all " <<
           attemptLimit << " attempts while writing " <<
           toWrite << '/' << ipcIo.len << " at " << ipcIo.offset << '+' <<
           wroteSoFar);
    return; // not a fatal I/O error, unless the caller treats it as such
}

static void
diskerWrite(IpcIoMsg &ipcIo)
{
    diskerWriteAttempts(ipcIo); // may fail
    Ipc::Mem::PutPage(ipcIo.page);
}

void
IpcIoFile::DiskerHandleMoreRequests(void *source)
{
    debugs(47, 7, HERE << "resuming handling requests after " <<
           static_cast<const char *>(source));
    DiskerHandleMoreRequestsScheduled = false;
    IpcIoFile::DiskerHandleRequests();
}

bool
IpcIoFile::WaitBeforePop()
{
    const int ioRate = queue->localRateLimit().load();
    const double maxRate = ioRate/1e3; // req/ms

    // do we need to enforce configured I/O rate?
    if (maxRate <= 0)
        return false;

    // is there an I/O request we could potentially delay?
    int processId;
    IpcIoMsg ipcIo;
    if (!queue->peek(processId, ipcIo)) {
        // unlike pop(), peek() is not reliable and does not block reader
        // so we must proceed with pop() even if it is likely to fail
        return false;
    }

    static timeval LastIo = current_time;

    const double ioDuration = 1.0 / maxRate; // ideal distance between two I/Os
    // do not accumulate more than 100ms or 100 I/Os, whichever is smaller
    const int64_t maxImbalance = min(static_cast<int64_t>(100), static_cast<int64_t>(100 * ioDuration));

    const double credit = ioDuration; // what the last I/O should have cost us
    const double debit = tvSubMsec(LastIo, current_time); // actual distance from the last I/O
    LastIo = current_time;

    Ipc::QueueReader::Balance &balance = queue->localBalance();
    balance += static_cast<int64_t>(credit - debit);

    debugs(47, 7, HERE << "rate limiting balance: " << balance << " after +" << credit << " -" << debit);

    if (ipcIo.command == IpcIo::cmdWrite && balance > maxImbalance) {
        // if the next request is (likely) write and we accumulated
        // too much time for future slow I/Os, then shed accumulated
        // time to keep just half of the excess
        const int64_t toSpend = balance - maxImbalance/2;

        if (toSpend/1e3 > Timeout)
            debugs(47, DBG_IMPORTANT, "WARNING: " << DbName << " delays " <<
                   "I/O requests for " << (toSpend/1e3) << " seconds " <<
                   "to obey " << ioRate << "/sec rate limit");

        debugs(47, 3, HERE << "rate limiting by " << toSpend << " ms to get" <<
               (1e3*maxRate) << "/sec rate");
        eventAdd("IpcIoFile::DiskerHandleMoreRequests",
                 &IpcIoFile::DiskerHandleMoreRequests,
                 const_cast<char*>("rate limiting"),
                 toSpend/1e3, 0, false);
        DiskerHandleMoreRequestsScheduled = true;
        return true;
    } else if (balance < -maxImbalance) {
        // do not owe "too much" to avoid "too large" bursts of I/O
        balance = -maxImbalance;
    }

    return false;
}

void
IpcIoFile::DiskerHandleRequests()
{
    // Balance our desire to maximize the number of concurrent I/O requests
    // (reordred by OS to minimize seek time) with a requirement to
    // send 1st-I/O notification messages, process Coordinator events, etc.
    const int maxSpentMsec = 10; // keep small: most RAM I/Os are under 1ms
    const timeval loopStart = current_time;

    int popped = 0;
    int workerId = 0;
    IpcIoMsg ipcIo;
    while (!WaitBeforePop() && queue->pop(workerId, ipcIo)) {
        ++popped;

        // at least one I/O per call is guaranteed if the queue is not empty
        DiskerHandleRequest(workerId, ipcIo);

        getCurrentTime();
        const double elapsedMsec = tvSubMsec(loopStart, current_time);
        if (elapsedMsec > maxSpentMsec || elapsedMsec < 0) {
            if (!DiskerHandleMoreRequestsScheduled) {
                // the gap must be positive for select(2) to be given a chance
                const double minBreakSecs = 0.001;
                eventAdd("IpcIoFile::DiskerHandleMoreRequests",
                         &IpcIoFile::DiskerHandleMoreRequests,
                         const_cast<char*>("long I/O loop"),
                         minBreakSecs, 0, false);
                DiskerHandleMoreRequestsScheduled = true;
            }
            debugs(47, 3, HERE << "pausing after " << popped << " I/Os in " <<
                   elapsedMsec << "ms; " << (elapsedMsec/popped) << "ms per I/O");
            break;
        }
    }

    // TODO: consider using O_DIRECT with "elevator" optimization where we pop
    // requests first, then reorder the popped requests to optimize seek time,
    // then do I/O, then take a break, and come back for the next set of I/O
    // requests.
}

/// called when disker receives an I/O request
void
IpcIoFile::DiskerHandleRequest(const int workerId, IpcIoMsg &ipcIo)
{
    if (ipcIo.command != IpcIo::cmdRead && ipcIo.command != IpcIo::cmdWrite) {
        debugs(0, DBG_CRITICAL, "ERROR: " << DbName <<
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

    debugs(47, 7, HERE << "pushing " << SipcIo(workerId, ipcIo, KidIdentifier));

    try {
        if (queue->push(workerId, ipcIo))
            Notify(workerId); // must notify worker
    } catch (const Queue::Full &) {
        // The worker queue should not overflow because the worker should pop()
        // before push()ing and because if disker pops N requests at a time,
        // we should make sure the worker pop() queue length is the worker
        // push queue length plus N+1. XXX: implement the N+1 difference.
        debugs(47, DBG_IMPORTANT, "BUG: Worker I/O pop queue for " <<
               DbName << " overflow: " <<
               SipcIo(workerId, ipcIo, KidIdentifier)); // TODO: report queue len

        // the I/O request we could not push will timeout
    }
}

static bool
DiskerOpen(const SBuf &path, int flags, mode_t)
{
    assert(TheFile < 0);

    DbName = path;
    TheFile = file_open(DbName.c_str(), flags);

    if (TheFile < 0) {
        const int xerrno = errno;
        debugs(47, DBG_CRITICAL, "ERROR: cannot open " << DbName << ": " <<
               xstrerr(xerrno));
        return false;
    }

    ++store_open_disk_fd;
    debugs(79,3, "rock db opened " << DbName << ": FD " << TheFile);
    return true;
}

static void
DiskerClose(const SBuf &path)
{
    if (TheFile >= 0) {
        file_close(TheFile);
        debugs(79,3, HERE << "rock db closed " << path << ": FD " << TheFile);
        TheFile = -1;
        --store_open_disk_fd;
    }
    DbName.clear();
}

/// reports our needs for shared memory pages to Ipc::Mem::Pages
/// and initializes shared memory segments used by IpcIoFile
class IpcIoRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* RegisteredRunner API */
    IpcIoRr(): owner(NULL) {}
    virtual ~IpcIoRr();
    virtual void claimMemoryNeeds();

protected:
    /* Ipc::Mem::RegisteredRunner API */
    virtual void create();

private:
    Ipc::FewToFewBiQueue::Owner *owner;
};

RunnerRegistrationEntry(IpcIoRr);

void
IpcIoRr::claimMemoryNeeds()
{
    const int itemsCount = Ipc::FewToFewBiQueue::MaxItemsCount(
                               ::Config.workers, ::Config.cacheSwap.n_strands, QueueCapacity);
    // the maximum number of shared I/O pages is approximately the
    // number of queue slots, we add a fudge factor to that to account
    // for corner cases where I/O pages are created before queue
    // limits are checked or destroyed long after the I/O is dequeued
    Ipc::Mem::NotePageNeed(Ipc::Mem::PageId::ioPage,
                           static_cast<int>(itemsCount * 1.1));
}

void
IpcIoRr::create()
{
    if (Config.cacheSwap.n_strands <= 0)
        return;

    Must(!owner);
    owner = Ipc::FewToFewBiQueue::Init(ShmLabel, Config.workers, 1,
                                       Config.cacheSwap.n_strands,
                                       1 + Config.workers, sizeof(IpcIoMsg),
                                       QueueCapacity);
}

IpcIoRr::~IpcIoRr()
{
    delete owner;
}

