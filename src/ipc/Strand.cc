/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "ipc/Strand.h"
#include "ipc/StrandCoord.h"
#include "ipc/Messages.h"
#include "ipc/SharedListen.h"
#include "ipc/Kids.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "mgr/Forwarder.h"
#include "DiskIO/IpcIo/IpcIoFile.h" /* XXX: scope boundary violation */
#include "SwapDir.h" /* XXX: scope boundary violation */
#include "CacheManager.h"


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

    HereIamMessage ann(StrandCoord(KidIdentifier, getpid()));
    TypedMsgHdr message;
    ann.pack(message);
    SendMessage(coordinatorAddr, message);
    setTimeout(6, "Ipc::Strand::timeoutHandler"); // TODO: make 6 configurable?
}

void Ipc::Strand::receive(const TypedMsgHdr &message)
{
    debugs(54, 6, HERE << message.type());
    switch (message.type()) {

    case mtRegistration:
        handleRegistrationResponse(HereIamMessage(message));
        break;

    case mtSharedListenResponse:
        SharedListenJoined(SharedListenResponse(message));
        break;

    case mtIpcIoRequest:
        IpcIoFile::HandleRequest(IpcIoRequest(message));
        break;

    case mtIpcIoResponse:
        IpcIoFile::HandleResponse(message);
        break;

    case mtCacheMgrRequest:
        handleCacheMgrRequest(Mgr::Request(message));
        break;

    case mtCacheMgrResponse:
        handleCacheMgrResponse(Mgr::Response(message));
        break;

    default:
        debugs(54, 1, HERE << "Unhandled message type: " << message.type());
        break;
    }
}

void Ipc::Strand::handleRegistrationResponse(const HereIamMessage &msg)
{
    // handle registration response from the coordinator; it could be stale
    if (msg.strand.kidId == KidIdentifier && msg.strand.pid == getpid()) {
        debugs(54, 6, "kid" << KidIdentifier << " registered");
        clearTimeout(); // we are done
    } else {
        // could be an ACK to the registration message of our dead predecessor
        debugs(54, 6, "kid" << KidIdentifier << " is not yet registered");
        // keep listening, with a timeout
    }
}

void Ipc::Strand::handleCacheMgrRequest(const Mgr::Request& request)
{
    Mgr::Action::Pointer action =
        CacheManager::GetInstance()->createRequestedAction(request.params);
    action->respond(request);
}

void Ipc::Strand::handleCacheMgrResponse(const Mgr::Response& response)
{
    Mgr::Forwarder::HandleRemoteAck(response.requestId);
}

void Ipc::Strand::timedout()
{
    debugs(54, 6, HERE << isRegistered);
    if (!isRegistered)
        fatalf("kid%d registration timed out", KidIdentifier);
}
