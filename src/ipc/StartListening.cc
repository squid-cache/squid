/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/AsyncCallbacks.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "ipc/SharedListen.h"
#include "ipc/StartListening.h"
#include "tools.h"

#include <cerrno>

std::ostream &
Ipc::operator <<(std::ostream &os, const StartListeningAnswer &answer)
{
    os << answer.conn;
    if (answer.errNo)
        os << ", err=" << answer.errNo;
    return os;
}

void
Ipc::StartListening(int sock_type, int proto, const Comm::ConnectionPointer &listenConn,
                    const FdNoteId fdNote, StartListeningCallback &callback)
{
    auto &answer = callback.answer();
    answer.conn = listenConn;

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
        JoinSharedListen(p, callback);
        return; // wait for the call back
    }

    enter_suid();
    comm_open_listener(sock_type, proto, answer.conn, FdNote(fdNote));
    const auto savedErrno = errno;
    leave_suid();

    answer.errNo = Comm::IsConnOpen(answer.conn) ? 0 : savedErrno;

    debugs(54, 3, "opened listen " << answer);
    ScheduleCallHere(callback.release());
}

