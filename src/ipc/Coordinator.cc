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

    default:
        debugs(54, 6, HERE << "Unhandled message type: " << message.type());
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
