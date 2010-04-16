/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "ipc/Coordinator.h"


CBDATA_NAMESPACED_CLASS_INIT(Ipc, Coordinator);


Ipc::Coordinator::Coordinator():
    Port(coordinatorPathAddr)
{
}

void Ipc::Coordinator::start()
{
    listen();
}

Ipc::StrandData* Ipc::Coordinator::findStrand(int kidId)
{
    for (Vector<StrandData>::iterator iter = strands.begin(); iter != strands.end(); ++iter) {
        if (iter->kidId == kidId)
            return &(*iter);
    }
    return NULL;
}

void Ipc::Coordinator::enrollStrand(const StrandData& strand)
{
    if (StrandData* found = findStrand(strand.kidId))
        *found = strand;
    else
        strands.push_back(strand);
}

void Ipc::Coordinator::handleRead(const Message& message)
{
    switch (message.type()) {
    case mtRegister:
        debugs(54, 6, HERE << "Registration request");
        handleRegistrationRequest(message.strand());
        break;

    default:
        debugs(54, 6, HERE << "Unhandled message of type: " << message.type());
        break;
    }
}

void Ipc::Coordinator::handleRegistrationRequest(const StrandData& strand)
{
    // register strand
    enrollStrand(strand);
    // send back received message
    SendMessage(makeAddr(strandPathAddr, strand.kidId), Message(mtRegister, strand.kidId, strand.pid));
}
