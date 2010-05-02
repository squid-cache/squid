/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "comm.h"
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

    case mtDescriptorGet:
        debugs(54, 6, HERE << "Descriptor get request");
        handleDescriptorGet(Descriptor(message));
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
    const int sock = (i != listeners.end()) ?
        i->second : openListenSocket(request, errNo);

    debugs(54, 3, HERE << "sending shared listen FD " << sock << " for " <<
        request.params.addr << " to kid" << request.requestorId <<
        " mapId=" << request.mapId);

    SharedListenResponse response(sock, errNo, request.mapId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, request.requestorId), message);
}

int
Ipc::Coordinator::openListenSocket(const SharedListenRequest& request,
        int &errNo)
{
    const OpenListenerParams &p = request.params;

    debugs(54, 6, HERE << "opening listen FD at " << p.addr << " for kid" <<
        request.requestorId);

    IpAddress addr = p.addr; // comm_open_listener may modify it

    enter_suid();
    const int sock = comm_open_listener(p.sock_type, p.proto, addr, p.flags,
        FdNote(p.fdNote));
    errNo = (sock >= 0) ? 0 : errno;
    leave_suid();

    // cache positive results
    if (sock >= 0)
        listeners[request.params] = sock;

    return sock;
}

void Ipc::Coordinator::handleDescriptorGet(const Descriptor& request)
{
    // XXX: hack: create descriptor here
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "/tmp/squid_shared_file.txt");
    static int fd = -1;
    if (fd < 0) {
        fd = open(buffer, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        int n = snprintf(buffer, sizeof(buffer), "coord: created %d\n", fd);
        ssize_t bytes = write(fd, buffer, n);
        Must(bytes == n);
        debugs(54, 6, "Created FD " << fd << " for kid" << request.fromKid);
    } else {
        int n = snprintf(buffer, sizeof(buffer), "coord: updated %d\n", fd);
        ssize_t bytes = write(fd, buffer, n);
        Must(bytes == n);
    }

    debugs(54, 6, "Sending FD " << fd << " to kid" << request.fromKid);

    Descriptor response(-1, fd);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, request.fromKid), message);

    // XXX: close(fd); fd should be opened until the message has not reached rec iver 
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
