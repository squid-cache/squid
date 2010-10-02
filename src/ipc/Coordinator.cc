/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "base/Subscription.h"
#include "comm.h"
#include "comm/Connection.h"
#include "ipc/Coordinator.h"
#include "ipc/FdNotes.h"
#include "ipc/SharedListen.h"


CBDATA_NAMESPACED_CLASS_INIT(Ipc, Coordinator);
Ipc::Coordinator* Ipc::Coordinator::TheInstance = NULL;


Ipc::Coordinator::Coordinator():
        Port(coordinatorAddr)
{
}

void Ipc::Coordinator::start()
{
    Port::start();
}

Ipc::StrandCoord* Ipc::Coordinator::findStrand(int kidId)
{
    typedef Strands::iterator SI;
    for (SI iter = strands.begin(); iter != strands.end(); ++iter) {
        if (iter->kidId == kidId)
            return &(*iter);
    }
    return NULL;
}

void Ipc::Coordinator::registerStrand(const StrandCoord& strand)
{
    if (StrandCoord* found = findStrand(strand.kidId))
        *found = strand;
    else
        strands.push_back(strand);
}

void Ipc::Coordinator::receive(const TypedMsgHdr& message)
{
    switch (message.type()) {
    case mtRegistration:
        debugs(54, 6, HERE << "Registration request");
        handleRegistrationRequest(StrandCoord(message));
        break;

    case mtSharedListenRequest:
        debugs(54, 6, HERE << "Shared listen request");
        handleSharedListenRequest(SharedListenRequest(message));
        break;

    default:
        debugs(54, 1, HERE << "Unhandled message type: " << message.type());
        break;
    }
}

void Ipc::Coordinator::handleRegistrationRequest(const StrandCoord& strand)
{
    registerStrand(strand);

    // send back an acknowledgement; TODO: remove as not needed?
    TypedMsgHdr message;
    strand.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, strand.kidId), message);
}

void
Ipc::Coordinator::handleSharedListenRequest(const SharedListenRequest& request)
{
    debugs(54, 4, HERE << "kid" << request.requestorId <<
           " needs shared listen FD for " << request.params.addr);
    Listeners::const_iterator i = listeners.find(request.params);
    int errNo = 0;
    const Comm::ConnectionPointer c = (i != listeners.end()) ?
                     i->second : openListenSocket(request, errNo);

    debugs(54, 3, HERE << "sending shared listen " << c << " for " <<
           request.params.addr << " to kid" << request.requestorId <<
           " mapId=" << request.mapId);

    SharedListenResponse response(c, errNo, request.mapId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, request.requestorId), message);
}

Comm::ConnectionPointer
Ipc::Coordinator::openListenSocket(const SharedListenRequest& request,
                                   int &errNo)
{
    const OpenListenerParams &p = request.params;

    debugs(54, 6, HERE << "opening listen FD at " << p.addr << " for kid" <<
           request.requestorId);

    Comm::ConnectionPointer conn = new Comm::Connection;
    conn->local = p.addr; // comm_open_listener may modify it
    conn->flags = p.flags;

    enter_suid();
    comm_open_listener(p.sock_type, p.proto, conn, FdNote(p.fdNote));
    errNo = Comm::IsConnOpen(conn) ? 0 : errno;
    leave_suid();

    debugs(54, 6, HERE << "tried listening on " << conn << " for kid" <<
           request.requestorId);

    // cache positive results
    if (Comm::IsConnOpen(conn))
        listeners[request.params] = conn;

    return conn;
}

void Ipc::Coordinator::broadcastSignal(int sig) const
{
    typedef Strands::const_iterator SCI;
    for (SCI iter = strands.begin(); iter != strands.end(); ++iter) {
        debugs(54, 5, HERE << "signal " << sig << " to kid" << iter->kidId <<
               ", PID=" << iter->pid);
        kill(iter->pid, sig);
    }
}

Ipc::Coordinator* Ipc::Coordinator::Instance()
{
    if (!TheInstance)
        TheInstance = new Coordinator;
    // XXX: if the Coordinator job quits, this pointer will become invalid
    // we could make Coordinator death fatal, except during exit, but since
    // Strands do not re-register, even process death would be pointless.
    return TheInstance;
}
