/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "squid.h"
#include "comm.h"
#include "CommCalls.h"
#include "comm/Connection.h"
#include "ipc/Port.h"

const char Ipc::coordinatorAddr[] = DEFAULT_STATEDIR "/coordinator.ipc";
const char Ipc::strandAddrPfx[] = DEFAULT_STATEDIR "/kid";

Ipc::Port::Port(const String& aListenAddr):
        UdsOp(aListenAddr)
{
    setOptions(COMM_NONBLOCKING | COMM_DOBIND);
}

void Ipc::Port::start()
{
    UdsOp::start();
    doListen();
}

void Ipc::Port::doListen()
{
    debugs(54, 6, HERE);
    buf.prepForReading();
    typedef CommCbMemFunT<Port, CommIoCbParams> Dialer;
    AsyncCall::Pointer readHandler = JobCallback(54, 6,
                                     Dialer, this, Port::noteRead);
    comm_read(conn(), buf.raw(), buf.size(), readHandler);
}

bool Ipc::Port::doneAll() const
{
    return false; // listen forever
}

String Ipc::Port::MakeAddr(const char* pathAddr, int id)
{
    assert(id >= 0);
    String addr = pathAddr;
    addr.append('-');
    addr.append(xitoa(id));
    addr.append(".ipc");
    return addr;
}

void Ipc::Port::noteRead(const CommIoCbParams& params)
{
    debugs(54, 6, HERE << params.conn << " flag " << params.flag <<
           " [" << this << ']');
    if (params.flag == COMM_OK) {
        assert(params.buf == buf.raw());
        receive(buf);
    }
    // TODO: if there was a fatal error on our socket, close the socket before
    // trying to listen again and print a level-1 error message.

    doListen();
}
