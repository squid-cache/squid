/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "ipc/Coordinator.h"


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
