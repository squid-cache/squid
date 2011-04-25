#ifndef SQUID_IPC_IOFILE_H
#define SQUID_IPC_IOFILE_H

#include "base/AsyncCall.h"
#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "ipc/forward.h"
#include "ipc/Queue.h"
#include <list>
#include <map>

// TODO: expand to all classes
namespace IpcIo {

/// what kind of I/O the disker needs to do or have done
typedef enum { cmdNone, cmdOpen, cmdRead, cmdWrite } Command;

enum { BufCapacity = 32*1024 };

} // namespace IpcIo


/// converts DiskIO requests to IPC queue messages
class IpcIoMsg {
public:
    IpcIoMsg();

public:
    unsigned int requestId; ///< unique for requestor; matches request w/ response

    char buf[IpcIo::BufCapacity]; // XXX: inefficient
    off_t offset;
    size_t len;

    IpcIo::Command command; ///< what disker is supposed to do or did

    int xerrno; ///< I/O error code or zero
};

class IpcIoPendingRequest;

class IpcIoFile: public DiskFile
{

public:
    typedef RefCount<IpcIoFile> Pointer;

    IpcIoFile(char const *aDb);
    virtual ~IpcIoFile();

    /* DiskFile API */
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
    static void HandleOpenResponse(const Ipc::StrandSearchResponse &response);

    /// handle queue push notifications from worker or disker
    static void HandleNotification(const Ipc::TypedMsgHdr &msg);

protected:
    friend class IpcIoPendingRequest;
    void openCompleted(const Ipc::StrandSearchResponse *const response);
    void readCompleted(ReadRequest *readRequest, const IpcIoMsg *const response);
    void writeCompleted(WriteRequest *writeRequest, const IpcIoMsg *const response);

private:
    void trackPendingRequest(IpcIoPendingRequest *const pending);
    void push(IpcIoPendingRequest *const pending);
    IpcIoPendingRequest *dequeueRequest(const unsigned int requestId);

    static void Notify(const int peerId);

    static void OpenTimeout(void *const param);
    static void CheckTimeouts(void *const param);
    void checkTimeouts();
    void scheduleTimeoutCheck();

    void handleNotification();
    void handleResponses(const char *when);
    void handleResponse(const IpcIoMsg &ipcIo);

    static void DiskerHandleRequests(const int workerId);
    static void DiskerHandleRequest(const int workerId, IpcIoMsg &ipcIo);

private:
    typedef FewToOneBiQueue DiskerQueue;
    typedef OneToOneBiQueue WorkerQueue;

    const String dbName; ///< the name of the file we are managing
    int diskId; ///< the process ID of the disker we talk to
    static DiskerQueue::Owner *diskerQueueOwner; ///< IPC queue owner for disker
    static DiskerQueue *diskerQueue; ///< IPC queue for disker
    WorkerQueue *workerQueue; ///< IPC queue for worker
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

    CBDATA_CLASS2(IpcIoFile);
};


/// keeps original I/O request parameters while disker is handling the request
class IpcIoPendingRequest
{
public:
    IpcIoPendingRequest(const IpcIoFile::Pointer &aFile);

    /// called when response is received and, with a nil response, on timeouts
    void completeIo(const IpcIoMsg *const response);

public:
    const IpcIoFile::Pointer file; ///< the file object waiting for the response
    ReadRequest *readRequest; ///< set if this is a read requests
    WriteRequest *writeRequest; ///< set if this is a write request

private:
    IpcIoPendingRequest(const IpcIoPendingRequest &d); // not implemented
    IpcIoPendingRequest &operator =(const IpcIoPendingRequest &d); // ditto
};


#endif /* SQUID_IPC_IOFILE_H */
