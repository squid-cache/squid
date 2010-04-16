/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "ipc/Port.h"


const char Ipc::coordinatorPathAddr[] = DEFAULT_PREFIX "/ipc/coordinator";
const char Ipc::strandPathAddr[] = DEFAULT_PREFIX "/ipc/squid";


Ipc::Port::Port(const String& aListenAddr):
    UdsOp(aListenAddr),
    listenAddr(aListenAddr)
{
    assert(listenAddr.size() > sizeof(DEFAULT_PREFIX));
}

void Ipc::Port::listen()
{
    debugs(54, 6, HERE);
    AsyncCall::Pointer readHandler = asyncCall(54, 6, "Ipc::Port::noteRead",
        CommCbMemFunT<Port, CommIoCbParams>(this, &Port::noteRead));
    comm_read(fd(), message.rawData(), message.size(), readHandler);
}

String Ipc::Port::makeAddr(const char* pathAddr, int id) const
{
    assert(id >= 0);
    String addr = pathAddr;
    addr.append('-');
    addr.append(xitoa(id));
    return addr;
}

void Ipc::Port::noteRead(const CommIoCbParams& params)
{
    debugs(54, 6, HERE << "FD " << params.fd << " flag " << params.flag << " [" << this << ']');
    assert(params.data == this);
    if (params.flag == COMM_OK) {
        assert(params.buf == (char*)&message);
        assert(params.size == sizeof(Message));
        handleRead(message);
    }
    listen();
}
