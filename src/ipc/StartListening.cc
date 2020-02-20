/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "ipc/SharedListen.h"
#include "ipc/StartListening.h"
#include "tools.h"

#include <cerrno>

Ipc::StartListeningCb::StartListeningCb(): conn(NULL), errNo(0)
{
}

Ipc::StartListeningCb::~StartListeningCb()
{
}

std::ostream &Ipc::StartListeningCb::startPrint(std::ostream &os) const
{
    return os << "(" << conn << ", err=" << errNo;
}

void
Ipc::StartListening(int sock_type, int proto, const Comm::ConnectionPointer &listenConn,
                    FdNoteId fdNote, AsyncCall::Pointer &callback)
{
    StartListeningCb *cbd = dynamic_cast<StartListeningCb*>(callback->getDialer());
    Must(cbd);
    cbd->conn = listenConn;

    const auto giveEachWorkerItsOwnQueue = listenConn->flags & COMM_REUSEPORT;
    if (!giveEachWorkerItsOwnQueue && UsingSmp()) {
        // Ask Coordinator for a listening socket.
        // All askers share one listening queue.
        OpenListenerParams p;
        p.sock_type = sock_type;
        p.proto = proto;
        p.addr = listenConn->local;
        p.flags = listenConn->flags;
        p.fdNote = fdNote;
        Ipc::JoinSharedListen(p, callback);
        return; // wait for the call back
    }

    enter_suid();
    comm_open_listener(sock_type, proto, cbd->conn, FdNote(fdNote));
    cbd->errNo = Comm::IsConnOpen(cbd->conn) ? 0 : errno;
    leave_suid();

    debugs(54, 3, HERE << "opened listen " << cbd->conn);
    ScheduleCallHere(callback);
}

