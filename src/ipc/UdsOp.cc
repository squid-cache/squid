/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "comm.h"
#include "ipc/UdsOp.h"

#define SEND_RETRIES 4
#define SEND_TIMEOUT 4

Ipc::Message::Message():
    data()
{
}

Ipc::Message::Message(MessageType messageType, int kidId, pid_t pid)
{
    data.messageType = messageType;
    data.strand.kidId = kidId;
    data.strand.pid = pid;
}

Ipc::MessageType Ipc::Message::type() const
{
    return data.messageType;
}

const Ipc::StrandData& Ipc::Message::strand() const
{
    return data.strand;
}

char* Ipc::Message::rawData()
{
    return (char*)&data;
}

size_t Ipc::Message::size()
{
    return sizeof(data);
}


Ipc::UdsOp::UdsOp(const String& pathAddr, bool bind /* = true */):
    AsyncJob("Ipc::UdsOp"),
    addr(setAddr(pathAddr)),
    options(COMM_NONBLOCKING),
    fd_(-1)
{
    debugs(54, 5, HERE << '[' << this << "] pathAddr " << pathAddr);
    if (bind) {
        unlink(pathAddr.termedBuf());
        options |= COMM_DOBIND;
    }
}

Ipc::UdsOp::~UdsOp()
{
    debugs(54, 5, HERE << '[' << this << ']');
    if (fd_ > 0)
        comm_close(fd_);
}

bool Ipc::UdsOp::doneAll() const
{
    return false;
}

int Ipc::UdsOp::fd()
{
    if (fd_ < 0) {
        fd_ = comm_open_uds(SOCK_DGRAM, 0, &addr, options);
        Must(fd_ > 0);
    }
    return fd_;
}

struct sockaddr_un Ipc::UdsOp::setAddr(const String& pathAddr)
{
    assert(pathAddr.size() != 0);
    struct sockaddr_un unixAddr;
    memset(&unixAddr, 0, sizeof(unixAddr));
    unixAddr.sun_family = AF_LOCAL;
    xstrncpy(unixAddr.sun_path, pathAddr.termedBuf(), sizeof(unixAddr.sun_path));
    return unixAddr;
}

void Ipc::UdsOp::setTimeout(AsyncCall::Pointer& timeoutHandler, int timeout)
{
    commSetTimeout(fd(), timeout, timeoutHandler);
}


CBDATA_NAMESPACED_CLASS_INIT(Ipc, UdsSender);

Ipc::UdsSender::UdsSender(const String& pathAddr, const Message& aMessage):
    UdsOp(pathAddr, false),
    message(aMessage),
    retries(SEND_RETRIES),
    timeout(SEND_TIMEOUT)
{
    assert(retries > 0);
    assert(timeout >= 0);
}

void Ipc::UdsSender::start()
{
    write();
    if (timeout > 0)
    {
        AsyncCall::Pointer timeoutHandler = asyncCall(54, 5, "Ipc::UdsSender::noteTimeout",
            CommCbMemFunT<UdsSender, CommTimeoutCbParams>(this, &UdsSender::noteTimeout));
        setTimeout(timeoutHandler, timeout);
    }
}

bool Ipc::UdsSender::retry()
{
    if (retries > 0)
        --retries;
    return retries != 0;
}

void Ipc::UdsSender::write()
{
    debugs(54, 5, HERE);
    AsyncCall::Pointer writeHandler = asyncCall(54, 5, "Ipc::UdsSender::noteWrite",
        CommCbMemFunT<UdsSender, CommIoCbParams>(this, &UdsSender::noteWrite));
    comm_write(fd(), message.rawData(), message.size(), writeHandler);
}

void Ipc::UdsSender::noteWrite(const CommIoCbParams& params)
{
    debugs(54, 5, HERE << "FD " << params.fd << " flag " << params.flag << " [" << this << ']');
    if (params.flag == COMM_OK || !retry())
        mustStop("done");
    else
        write();
}

void Ipc::UdsSender::noteTimeout(const CommTimeoutCbParams& params)
{
    debugs(54, 5, HERE);
    mustStop("done");
}


void Ipc::SendMessage(const String& toAddress, const Message& message)
{
    AsyncJob::AsyncStart(new UdsSender(toAddress, message));
}
