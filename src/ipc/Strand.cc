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
    Port(makeAddr(strandPathAddr, KidIdentifier)),
    isRegistered(false)
{
}

void Ipc::Strand::start()
{
    listen();
    setListenTimeout(&Strand::noteRegistrationTimeout, 6);
    enroll();
}

void Ipc::Strand::enroll()
{
    debugs(54, 6, HERE);
    assert(!registered());
    SendMessage(coordinatorPathAddr, Message(mtRegister, KidIdentifier, getpid()));
}

void Ipc::Strand::handleRead(const Message& message)
{
    debugs(54, 6, HERE);
    switch (message.type()) {

    case mtRegister:
        handleRegistrationResponse(message.strand());
        break;

    default:
        debugs(54, 6, HERE << "Unhandled message of type: " << message.type());
        break;
    }
}

void Ipc::Strand::handleRegistrationResponse(const StrandData& strand)
{
    // handle registration respond from coordinator
    // coordinator returns the same message
    isRegistered = (strand.kidId == KidIdentifier && strand.pid == getpid());
    debugs(54, 6, "Kid " << KidIdentifier << " is " << (char*)(isRegistered ? "" : "NOT ") << "registered");
    setListenTimeout(NULL, -1);
}

void Ipc::Strand::setListenTimeout(TimeoutHandler timeoutHandler, int timeout)
{
    AsyncCall::Pointer listenTimeoutHandler = NULL;
    if (timeout > 0) {
        assert(timeoutHandler != NULL);
        listenTimeoutHandler = asyncCall(54, 6, "Ipc::Strand::timeoutHandler",
            CommCbMemFunT<Strand, CommTimeoutCbParams>(this, timeoutHandler));
    }
    setTimeout(listenTimeoutHandler, timeout);
}

void Ipc::Strand::noteRegistrationTimeout(const CommTimeoutCbParams& params)
{
    debugs(54, 6, HERE);
    if (!registered()) {
        debugs(54, 6, HERE << "Kid " << KidIdentifier << " is not registered");
        exit(1);
    }
}

bool Ipc::Strand::registered() const
{
    return isRegistered;
}
