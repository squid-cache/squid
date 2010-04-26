/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "comm.h"
#include "ipc/UdsOp.h"


Ipc::Message::Message()
{
    data.messageType = mtNone;
    data.strand.kidId = -1;
}

Ipc::Message::Message(MessageType messageType, int kidId, pid_t pid)
{
    data.messageType = messageType;
    data.strand.kidId = kidId;
    data.strand.pid = pid;
}

const Ipc::StrandData &Ipc::Message::strand() const
{
    Must(data.messageType == mtRegistration);
	return data.strand;
}

Ipc::UdsOp::UdsOp(const String& pathAddr):
    AsyncJob("Ipc::UdsOp"),
    addr(setAddr(pathAddr)),
    options(COMM_NONBLOCKING),
    fd_(-1)
{
    debugs(54, 5, HERE << '[' << this << "] pathAddr=" << pathAddr);
}

Ipc::UdsOp::~UdsOp()
{
    debugs(54, 5, HERE << '[' << this << ']');
    if (fd_ >= 0)
        comm_close(fd_);
}

void Ipc::UdsOp::setOptions(int newOptions)
{
    options = newOptions;
}

int Ipc::UdsOp::fd()
{
    if (fd_ < 0) {
        if (options & COMM_DOBIND)
            unlink(addr.sun_path);
        fd_ = comm_open_uds(SOCK_DGRAM, 0, &addr, options);
        Must(fd_ >= 0);
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

void Ipc::UdsOp::setTimeout(int seconds, const char *handlerName)
{
    AsyncCall::Pointer handler = asyncCall(54,5, handlerName,
        CommCbMemFunT<UdsOp, CommTimeoutCbParams>(this,
            &UdsOp::noteTimeout));
    commSetTimeout(fd(), seconds, handler);
}

void Ipc::UdsOp::clearTimeout()
{
    commSetTimeout(fd(), -1, NULL, NULL); // TODO: add Comm::ClearTimeout(fd)
}

void Ipc::UdsOp::noteTimeout(const CommTimeoutCbParams &)
{
    timedout(); // our kid handles communication timeout
}


CBDATA_NAMESPACED_CLASS_INIT(Ipc, UdsSender);

Ipc::UdsSender::UdsSender(const String& pathAddr, const Message& aMessage):
    UdsOp(pathAddr),
    message(aMessage),
    retries(4), // TODO: make configurable?
    timeout(5), // TODO: make configurable?
    writing(false)
{
}

void Ipc::UdsSender::start()
{
    UdsOp::start();
    write();
    if (timeout > 0)
        setTimeout(timeout, "Ipc::UdsSender::noteTimeout");
}

bool Ipc::UdsSender::doneAll() const
{
    return !writing && UdsOp::doneAll();
}

void Ipc::UdsSender::write()
{
    debugs(54, 5, HERE);
    AsyncCall::Pointer writeHandler = asyncCall(54, 5, "Ipc::UdsSender::wrote",
        CommCbMemFunT<UdsSender, CommIoCbParams>(this, &UdsSender::wrote));
    comm_write(fd(), message.raw(), message.size(), writeHandler);
    writing = true;
}

void Ipc::UdsSender::wrote(const CommIoCbParams& params)
{
    debugs(54, 5, HERE << "FD " << params.fd << " flag " << params.flag << " [" << this << ']');
    writing = false;
    if (params.flag != COMM_OK && retries-- > 0)
        write(); // XXX: should we close on error so that fd() reopens?
}

void Ipc::UdsSender::timedout()
{
    debugs(54, 5, HERE);
    mustStop("timedout");
}


void Ipc::SendMessage(const String& toAddress, const Message& message)
{
    AsyncJob::AsyncStart(new UdsSender(toAddress, message));
}
