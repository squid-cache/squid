/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "CommCalls.h"
#include "ipc/Port.h"
#include "tools.h"

static const char channelPathPfx[] = DEFAULT_STATEDIR "/";
static const char coordinatorAddrLabel[] = "-coordinator";
const char Ipc::strandAddrLabel[] =  "-kid";

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

String Ipc::Port::MakeAddr(const char* processLabel, int id)
{
    assert(id >= 0);
    String addr = channelPathPfx;
    addr.append(service_name.c_str());
    addr.append(processLabel);
    addr.append('-');
    addr.append(xitoa(id));
    addr.append(".ipc");
    return addr;
}

String
Ipc::Port::CoordinatorAddr()
{
    static String coordinatorAddr;
    if (!coordinatorAddr.size()) {
        coordinatorAddr= channelPathPfx;
        coordinatorAddr.append(service_name.c_str());
        coordinatorAddr.append(coordinatorAddrLabel);
        coordinatorAddr.append(".ipc");
    }
    return coordinatorAddr;
}

void Ipc::Port::noteRead(const CommIoCbParams& params)
{
    debugs(54, 6, HERE << params.conn << " flag " << params.flag <<
           " [" << this << ']');
    if (params.flag == Comm::OK) {
        assert(params.buf == buf.raw());
        receive(buf);
    }
    // TODO: if there was a fatal error on our socket, close the socket before
    // trying to listen again and print a level-1 error message.

    doListen();
}

