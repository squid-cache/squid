/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "CollapsedForwarding.h"
#include "comm/Connection.h"
#include "fatal.h"
#include "globals.h"
#include "ipc/Kids.h"
#include "ipc/Messages.h"
#include "ipc/QuestionerId.h"
#include "ipc/SharedListen.h"
#include "ipc/Strand.h"
#include "ipc/StrandCoord.h"
#include "ipc/StrandSearch.h"
#include "mgr/Forwarder.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#if HAVE_DISKIO_MODULE_IPCIO
#include "DiskIO/IpcIo/IpcIoFile.h" /* XXX: scope boundary violation */
#endif
#if SQUID_SNMP
#include "snmp/Forwarder.h"
#include "snmp/Request.h"
#include "snmp/Response.h"
#endif

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Strand);

Ipc::Strand::Strand():
    Port(MakeAddr(strandAddrLabel, KidIdentifier)),
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

    StrandMessage::NotifyCoordinator(mtRegisterStrand, nullptr);
    setTimeout(6, "Ipc::Strand::timeoutHandler"); // TODO: make 6 configurable?
}

void Ipc::Strand::receive(const TypedMsgHdr &message)
{
    switch (message.rawType()) {

    case mtStrandRegistered:
        handleRegistrationResponse(Mine(StrandMessage(message)));
        break;

    case mtSharedListenResponse:
        SharedListenJoined(Mine(SharedListenResponse(message)));
        break;

#if HAVE_DISKIO_MODULE_IPCIO
    case mtStrandReady:
        IpcIoFile::HandleOpenResponse(Mine(StrandMessage(message)));
        break;

    case mtIpcIoNotification:
        IpcIoFile::HandleNotification(message);
        break;
#endif /* HAVE_DISKIO_MODULE_IPCIO */

    case mtCacheMgrRequest: {
        const Mgr::Request req(message);
        handleCacheMgrRequest(req);
    }
    break;

    case mtCacheMgrResponse: {
        const Mgr::Response resp(message);
        handleCacheMgrResponse(Mine(resp));
    }
    break;

    case mtCollapsedForwardingNotification:
        CollapsedForwarding::HandleNotification(message);
        break;

#if SQUID_SNMP
    case mtSnmpRequest: {
        const Snmp::Request req(message);
        handleSnmpRequest(req);
    }
    break;

    case mtSnmpResponse: {
        const Snmp::Response resp(message);
        handleSnmpResponse(Mine(resp));
    }
    break;
#endif

    default:
        Port::receive(message);
        break;
    }
}

void
Ipc::Strand::handleRegistrationResponse(const StrandMessage &msg)
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

#if SQUID_SNMP
void Ipc::Strand::handleSnmpRequest(const Snmp::Request& request)
{
    debugs(54, 6, HERE);
    Snmp::SendResponse(request.requestId, request.pdu);
}

void Ipc::Strand::handleSnmpResponse(const Snmp::Response& response)
{
    debugs(54, 6, HERE);
    Snmp::Forwarder::HandleRemoteAck(response.requestId);
}
#endif

void Ipc::Strand::timedout()
{
    debugs(54, 6, HERE << isRegistered);
    if (!isRegistered)
        fatalf("kid%d registration timed out", KidIdentifier);
}

