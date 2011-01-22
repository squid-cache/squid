/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "comm.h"
#include "ipc/SharedListen.h"
#include "ipc/StartListening.h"


Ipc::StartListeningCb::StartListeningCb(): fd(-1), errNo(0)
{
}

Ipc::StartListeningCb::~StartListeningCb()
{
}

std::ostream &Ipc::StartListeningCb::startPrint(std::ostream &os) const
{
    return os << "(FD " << fd << ", err=" << errNo;
}

void
Ipc::StartListening(int sock_type, int proto, Ip::Address &addr, int flags,
                    FdNoteId fdNote, AsyncCall::Pointer &callback)
{
    if (UsingSmp()) { // if SMP is on, share
        OpenListenerParams p;
        p.sock_type = sock_type;
        p.proto = proto;
        p.addr = addr;
        p.flags = flags;
        p.fdNote = fdNote;
        Ipc::JoinSharedListen(p, callback);
        return; // wait for the call back
    }

    StartListeningCb *cbd = dynamic_cast<StartListeningCb*>(callback->getDialer());
    Must(cbd);

    enter_suid();
    cbd->fd = comm_open_listener(sock_type, proto, addr, flags, FdNote(fdNote));
    cbd->errNo = cbd->fd >= 0 ? 0 : errno;
    leave_suid();

    debugs(54, 3, HERE << "opened listen FD " << cbd->fd << " on " << addr);
    ScheduleCallHere(callback);
}
