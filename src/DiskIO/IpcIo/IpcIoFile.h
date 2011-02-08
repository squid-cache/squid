#ifndef SQUID_IPC_IOFILE_H
#define SQUID_IPC_IOFILE_H

#include "base/AsyncCall.h"
#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "ipc/forward.h"
#include <map>

// TODO: expand to all classes
namespace IpcIo {

/// what kind of I/O the disker needs to do or have done
typedef enum { cmdNone, cmdOpen, cmdRead, cmdWrite } Command;

enum { BufCapacity = 32*1024 }; // XXX: must not exceed TypedMsgHdr.maxSize

} // namespace IpcIo


/// converts DiskIO requests to IPC messages
// TODO: make this IpcIoMsg to make IpcIoRequest and IpcIoResponse similar
class IpcIoRequest {
public:
    IpcIoRequest();

    explicit IpcIoRequest(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()
    void pack(Ipc::TypedMsgHdr& msg) const; ///< prepare for sendmsg()

public:
    int requestorId; ///< kidId of the requestor; used for response destination
    unsigned int requestId; ///< unique for sender; matches request w/ response

    /* ReadRequest and WriteRequest parameters to pass to disker */
    char buf[IpcIo::BufCapacity]; // XXX: inefficient
    off_t offset;
    size_t len;

    IpcIo::Command command; ///< what disker is supposed to do
};

/// disker response to IpcIoRequest
class IpcIoResponse {
public:
    IpcIoResponse();

    explicit IpcIoResponse(const Ipc::TypedMsgHdr& msg); ///< from recvmsg()
    void pack(Ipc::TypedMsgHdr& msg) const; ///< prepare for sendmsg()

public:
    int diskId; ///< kidId of the responding disker
    unsigned int requestId; ///< unique for sender; matches request w/ response

    char buf[IpcIo::BufCapacity]; // XXX: inefficient
    size_t len;

    IpcIo::Command command; ///< what disker did

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

    /// finds and calls the right IpcIoFile upon disker's response
    static void HandleResponse(const Ipc::TypedMsgHdr &response);

    /// disker entry point for remote I/O requests
    static void HandleRequest(const IpcIoRequest &request);

protected:
    friend class IpcIoPendingRequest;
    void openCompleted(const IpcIoResponse *response);
    void readCompleted(ReadRequest *readRequest, const IpcIoResponse *);
    void writeCompleted(WriteRequest *writeRequest, const IpcIoResponse *);

private:
    void send(IpcIoRequest &request, IpcIoPendingRequest *pending);

    static IpcIoPendingRequest *DequeueRequest(unsigned int requestId);

    static void CheckTimeouts(void* param);
    static void ScheduleTimeoutCheck();

private:
    const String dbName; ///< the name of the file we are managing
    int diskId; ///< the process ID of the disker we talk to
    RefCount<IORequestor> ioRequestor;

    int ioLevel; ///< number of pending I/O requests using this file

    bool error_; ///< whether we have seen at least one I/O error (XXX)

    /// maps requestId to the handleResponse callback
    typedef std::map<unsigned int, IpcIoPendingRequest*> RequestMap;
    static RequestMap TheRequestMap1; ///< older (or newer) pending requests
    static RequestMap TheRequestMap2; ///< newer (or older) pending requests
    static RequestMap *TheOlderRequests; ///< older requests (map1 or map2)
    static RequestMap *TheNewerRequests; ///< newer requests (map2 or map1)
    static bool TimeoutCheckScheduled; ///< we expect a CheckTimeouts() call

    static unsigned int LastRequestId; ///< last requestId used

    CBDATA_CLASS2(IpcIoFile);
};


/// keeps original I/O request parameters while disker is handling the request
class IpcIoPendingRequest
{
public:
    IpcIoPendingRequest(const IpcIoFile::Pointer &aFile);

    /// called when response is received and, with a nil response, on timeouts
    void completeIo(IpcIoResponse *response);

public:
    IpcIoFile::Pointer file; ///< the file object waiting for the response
    ReadRequest *readRequest; ///< set if this is a read requests
    WriteRequest *writeRequest; ///< set if this is a write request

private:
    IpcIoPendingRequest(const IpcIoPendingRequest &d); // not implemented
    IpcIoPendingRequest &operator =(const IpcIoPendingRequest &d); // ditto
};


#endif /* SQUID_IPC_IOFILE_H */
