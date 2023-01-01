/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_IOFILE_H
#define SQUID_IPC_IOFILE_H

#include "base/AsyncCall.h"
#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "ipc/forward.h"
#include "ipc/mem/Page.h"
#include "SquidString.h"
#include <list>
#include <map>
#include <memory>

namespace Ipc
{
class FewToFewBiQueue;
} // Ipc

// TODO: expand to all classes
namespace IpcIo
{

/// what kind of I/O the disker needs to do or have done
typedef enum { cmdNone, cmdOpen, cmdRead, cmdWrite } Command;

} // namespace IpcIo

/// converts DiskIO requests to IPC queue messages
class IpcIoMsg
{
public:
    IpcIoMsg();

public:
    unsigned int requestId; ///< unique for requestor; matches request w/ response

    off_t offset;
    size_t len;
    Ipc::Mem::PageId page;
    pid_t workerPid; ///< the process ID of the I/O requestor

    IpcIo::Command command; ///< what disker is supposed to do or did
    struct timeval start; ///< when the I/O request was converted to IpcIoMsg

    int xerrno; ///< I/O error code or zero
};

class IpcIoPendingRequest;

/// In a worker process, represents a single (remote) cache_dir disker file.
/// In a disker process, used as a bunch of static methods handling that file.
class IpcIoFile: public DiskFile
{
    CBDATA_CLASS(IpcIoFile);

public:
    typedef RefCount<IpcIoFile> Pointer;

    IpcIoFile(char const *aDb);
    virtual ~IpcIoFile();

    /* DiskFile API */
    virtual void configure(const Config &cfg);
    virtual void open(int flags, mode_t mode, RefCount<IORequestor> callback);
    virtual void create(int flags, mode_t mode, RefCount<IORequestor> callback);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close();
    virtual bool error() const;
    virtual int getFD() const;
    virtual bool canRead() const;
    virtual bool canWrite() const;
    virtual bool ioInProgress() const;

    /// handle open response from coordinator
    static void HandleOpenResponse(const Ipc::StrandMessage &);

    /// handle queue push notifications from worker or disker
    static void HandleNotification(const Ipc::TypedMsgHdr &msg);

    DiskFile::Config config; ///< supported configuration options

protected:
    friend class IpcIoPendingRequest;
    void openCompleted(const Ipc::StrandMessage *);
    void readCompleted(ReadRequest *readRequest, IpcIoMsg *const response);
    void writeCompleted(WriteRequest *writeRequest, const IpcIoMsg *const response);
    bool canWait() const;

private:
    void trackPendingRequest(const unsigned int id, IpcIoPendingRequest *const pending);
    void push(IpcIoPendingRequest *const pending);
    IpcIoPendingRequest *dequeueRequest(const unsigned int requestId);

    /// the total number of I/O requests in push queue and pop queue
    /// (but no, the implementation does not add push and pop queue sizes)
    size_t pendingRequests() const { return olderRequests->size() + newerRequests->size(); }

    static void Notify(const int peerId);

    static void OpenTimeout(void *const param);
    static void CheckTimeouts(void *const param);
    void checkTimeouts();
    void scheduleTimeoutCheck();

    static void HandleResponses(const char *const when);
    void handleResponse(IpcIoMsg &ipcIo);

    static void DiskerHandleMoreRequests(void*);
    static void DiskerHandleRequests();
    static void DiskerHandleRequest(const int workerId, IpcIoMsg &ipcIo);
    static bool WaitBeforePop();

    static void HandleMessagesAtStart();

private:
    const String dbName; ///< the name of the file we are managing
    const pid_t myPid; ///< optimization: cached process ID of our process
    int diskId; ///< the kid ID of the disker we talk to
    RefCount<IORequestor> ioRequestor;

    bool error_; ///< whether we have seen at least one I/O error (XXX)

    unsigned int lastRequestId; ///< last requestId used

    /// maps requestId to the handleResponse callback
    typedef std::map<unsigned int, IpcIoPendingRequest*> RequestMap;
    RequestMap requestMap1; ///< older (or newer) pending requests
    RequestMap requestMap2; ///< newer (or older) pending requests
    RequestMap *olderRequests; ///< older requests (map1 or map2)
    RequestMap *newerRequests; ///< newer requests (map2 or map1)
    bool timeoutCheckScheduled; ///< we expect a CheckTimeouts() call

    static const double Timeout; ///< timeout value in seconds

    typedef std::list<Pointer> IpcIoFileList;
    static IpcIoFileList WaitingForOpen; ///< pending open requests

    ///< maps diskerId to IpcIoFile, cleared in destructor
    typedef std::map<int, IpcIoFile*> IpcIoFilesMap;
    static IpcIoFilesMap IpcIoFiles;

    typedef Ipc::FewToFewBiQueue Queue;
    static std::unique_ptr<Queue> queue; ///< IPC queue

    /// whether we are waiting for an event to handle still queued I/O requests
    static bool DiskerHandleMoreRequestsScheduled;
};

/// keeps original I/O request parameters while disker is handling the request
class IpcIoPendingRequest
{
public:
    IpcIoPendingRequest(const IpcIoFile::Pointer &aFile);

    /// called when response is received and, with a nil response, on timeouts
    void completeIo(IpcIoMsg *const response);

public:
    const IpcIoFile::Pointer file; ///< the file object waiting for the response
    ReadRequest *readRequest; ///< set if this is a read requests
    WriteRequest *writeRequest; ///< set if this is a write request

    CodeContext::Pointer codeContext; ///< requestor's context

private:
    IpcIoPendingRequest(const IpcIoPendingRequest &d); // not implemented
    IpcIoPendingRequest &operator =(const IpcIoPendingRequest &d); // ditto
};

#endif /* SQUID_IPC_IOFILE_H */

