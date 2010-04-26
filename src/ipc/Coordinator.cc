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

Ipc::StrandData* Ipc::Coordinator::findStrand(int kidId)
{
    for (Vector<StrandData>::iterator iter = strands.begin(); iter != strands.end(); ++iter) {
        if (iter->kidId == kidId)
            return &(*iter);
    }
    return NULL;
}

void Ipc::Coordinator::registerStrand(const StrandData& strand)
{
    if (StrandData* found = findStrand(strand.kidId))
        *found = strand;
    else
        strands.push_back(strand);
}

void Ipc::Coordinator::receive(const Message& message)
{
    switch (message.type()) {
    case mtRegistration:
        debugs(54, 6, HERE << "Registration request");
        handleRegistrationRequest(message.strand());
        break;

    default:
        debugs(54, 6, HERE << "Unhandled message type: " << message.type());
        break;
    }
}

void Ipc::Coordinator::handleRegistrationRequest(const StrandData& strand)
{
    registerStrand(strand);

    // send back an acknowledgement; TODO: remove as not needed?
    SendMessage(MakeAddr(strandAddrPfx, strand.kidId),
        Message(mtRegistration, strand.kidId, strand.pid));
}

void Ipc::Coordinator::broadcastSignal(int sig) const
{
    typedef Vector<StrandData>::const_iterator VSDCI;
    for (VSDCI iter = strands.begin(); iter != strands.end(); ++iter) {
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
