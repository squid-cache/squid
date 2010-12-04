/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "comm.h"
#include "CommCalls.h"
#include "comm/Write.h"
#include "base/TextException.h"
#include "ipc/UdsOp.h"


Ipc::UdsOp::UdsOp(const String& pathAddr):
        AsyncJob("Ipc::UdsOp"),
        address(PathToAddress(pathAddr)),
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
            unlink(address.sun_path);
        fd_ = comm_open_uds(SOCK_DGRAM, 0, &address, options);
        Must(fd_ >= 0);
    }
    return fd_;
}

void Ipc::UdsOp::setTimeout(int seconds, const char *handlerName)
{
    typedef CommCbMemFunT<UdsOp, CommTimeoutCbParams> Dialer;
    AsyncCall::Pointer handler = asyncCall(54,5, handlerName,
                                           Dialer(CbcPointer<UdsOp>(this), &UdsOp::noteTimeout));
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


struct sockaddr_un
Ipc::PathToAddress(const String& pathAddr) {
    assert(pathAddr.size() != 0);
    struct sockaddr_un unixAddr;
    memset(&unixAddr, 0, sizeof(unixAddr));
    unixAddr.sun_family = AF_LOCAL;
    xstrncpy(unixAddr.sun_path, pathAddr.termedBuf(), sizeof(unixAddr.sun_path));
    return unixAddr;
}


CBDATA_NAMESPACED_CLASS_INIT(Ipc, UdsSender);

Ipc::UdsSender::UdsSender(const String& pathAddr, const TypedMsgHdr& aMessage):
        UdsOp(pathAddr),
        message(aMessage),
        retries(10), // TODO: make configurable?
        timeout(10), // TODO: make configurable?
        writing(false)
{
    message.address(address);
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
    typedef CommCbMemFunT<UdsSender, CommIoCbParams> Dialer;
    AsyncCall::Pointer writeHandler = JobCallback(54, 5,
                                      Dialer, this, UdsSender::wrote);
    Comm::Write(fd(), message.raw(), message.size(), writeHandler, NULL);
    writing = true;
}

void Ipc::UdsSender::wrote(const CommIoCbParams& params)
{
    debugs(54, 5, HERE << "FD " << params.fd << " flag " << params.flag << " [" << this << ']');
    writing = false;
    if (params.flag != COMM_OK && retries-- > 0) {
        sleep(1); // do not spend all tries at once; XXX: use an async timed event instead of blocking here; store the time when we started writing so that we do not sleep if not needed?
        write(); // XXX: should we close on error so that fd() reopens?
    }
}

void Ipc::UdsSender::timedout()
{
    debugs(54, 5, HERE);
    mustStop("timedout");
}


void Ipc::SendMessage(const String& toAddress, const TypedMsgHdr &message)
{
    AsyncJob::Start(new UdsSender(toAddress, message));
}
