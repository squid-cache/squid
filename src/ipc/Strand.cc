/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "ipc/Strand.h"
#include "ipc/Messages.h"
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
    TypedMsgHdr message;
    StrandCoord(KidIdentifier, getpid()).pack(message);
    SendMessage(coordinatorAddr, message);
    setTimeout(6, "Ipc::Strand::timeoutHandler"); // TODO: make 6 configurable?
}

void Ipc::Strand::receive(const TypedMsgHdr &message)
{
    debugs(54, 6, HERE << message.type());
    switch (message.type()) {

    case mtRegistration:
        handleRegistrationResponse(StrandCoord(message));
        break;

    case mtDescriptorPut:
        putDescriptor(Descriptor(message));
        break;

    default:
        debugs(54, 1, HERE << "Unhandled message type: " << message.type());
        break;
    }
}

void Ipc::Strand::handleRegistrationResponse(const StrandCoord &strand)
{
    // handle registration response from the coordinator; it could be stale
    if (strand.kidId == KidIdentifier && strand.pid == getpid()) {
        debugs(54, 6, "kid" << KidIdentifier << " registered");
        clearTimeout(); // we are done

        debugs(54, 6, HERE << "requesting FD");
        Descriptor request(KidIdentifier, -1);
        TypedMsgHdr message;
        request.pack(message);
        SendMessage(coordinatorAddr, message);
    } else {
        // could be an ACK to the registration message of our dead predecessor
        debugs(54, 6, "kid" << KidIdentifier << " is not yet registered");
        // keep listening, with a timeout
    }
}

/// receive descriptor we asked for
void Ipc::Strand::putDescriptor(const Descriptor &message)
{
    debugs(54, 6, HERE << "got FD " << message.fd);
    char buffer[64];
    const int n = snprintf(buffer, sizeof(buffer), "strand: kid%d wrote using FD %d\n", KidIdentifier, message.fd);
    ssize_t bytes = write(message.fd, buffer, n);
    Must(bytes == n);
}

void Ipc::Strand::timedout()
{
    debugs(54, 6, HERE << isRegistered);
    if (!isRegistered)
        fatalf("kid%d registration timed out", KidIdentifier);
}
