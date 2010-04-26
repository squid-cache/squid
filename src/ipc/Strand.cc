/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "ipc/Strand.h"
#include "ipc/Kids.h"


CBDATA_NAMESPACED_CLASS_INIT(Ipc, Strand);


Ipc::Strand::Strand():
    Port(MakeAddr(strandAddrPfx, KidIdentifier)),
    isRegistered(false)
{
}

void Ipc::Strand::start()
{
    Port::start();
    registerSelf();
}

void Ipc::Strand::registerSelf()
{
    debugs(54, 6, HERE);
    Must(!isRegistered);
    SendMessage(coordinatorAddr,
		Message(mtRegistration, KidIdentifier, getpid()));
    setTimeout(6, "Ipc::Strand::timeoutHandler"); // TODO: make 6 configurable?
}

void Ipc::Strand::receive(const Message& message)
{
    debugs(54, 6, HERE);
    switch (message.type()) {

    case mtRegistration:
        handleRegistrationResponse(message.strand());
        break;

    default:
        debugs(54, 6, HERE << "Unhandled message type: " << message.type());
        break;
    }
}

void Ipc::Strand::handleRegistrationResponse(const StrandData& strand)
{
    // handle registration response from the coordinator; it could be stale
    if (strand.kidId == KidIdentifier && strand.pid == getpid()) {
        debugs(54, 6, "kid" << KidIdentifier << " registered");
        clearTimeout(); // we are done
    } else {
        // could be an ACK to the registration message of our dead predecessor
        debugs(54, 6, "kid" << KidIdentifier << " is not yet registered");
        // keep listening, with a timeout
    }
}

void Ipc::Strand::timedout()
{
    debugs(54, 6, HERE << isRegistered);
    if (!isRegistered)
        fatalf("kid%d registration timed out", KidIdentifier);
}
