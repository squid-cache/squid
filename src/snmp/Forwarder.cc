/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "comm.h"
#include "CommCalls.h"
#include "globals.h"
#include "ipc/Port.h"
#include "snmp/Forwarder.h"
#include "snmp/Request.h"
#include "snmp/Response.h"
#include "snmp_core.h"

CBDATA_NAMESPACED_CLASS_INIT(Snmp, Forwarder);

Snmp::Forwarder::Forwarder(const Pdu& aPdu, const Session& aSession, int aFd,
                           const Ip::Address& anAddress):
    Ipc::Forwarder(new Request(KidIdentifier, Ipc::RequestId(), aPdu, aSession, aFd, anAddress), 2),
    fd(aFd)
{
    debugs(49, 5, HERE << "FD " << aFd);
    Must(fd >= 0);
    closer = asyncCall(49, 5, "Snmp::Forwarder::noteCommClosed",
                       CommCbMemFunT<Forwarder, CommCloseCbParams>(this, &Forwarder::noteCommClosed));
    comm_add_close_handler(fd, closer);
}

/// removes our cleanup handler of the client connection socket
void
Snmp::Forwarder::swanSong()
{
    if (fd >= 0) {
        if (closer != NULL) {
            comm_remove_close_handler(fd, closer);
            closer = NULL;
        }
        fd = -1;
    }
    Ipc::Forwarder::swanSong();
}

/// called when the client socket gets closed by some external force
void
Snmp::Forwarder::noteCommClosed(const CommCloseCbParams& params)
{
    debugs(49, 5, HERE);
    Must(fd == params.fd);
    fd = -1;
    mustStop("commClosed");
}

void
Snmp::Forwarder::handleTimeout()
{
    sendError(SNMP_ERR_RESOURCEUNAVAILABLE);
    Ipc::Forwarder::handleTimeout();
}

void
Snmp::Forwarder::handleException(const std::exception& e)
{
    debugs(49, 3, HERE << e.what());
    if (fd >= 0)
        sendError(SNMP_ERR_GENERR);
    Ipc::Forwarder::handleException(e);
}

/// send error SNMP response
void
Snmp::Forwarder::sendError(int error)
{
    debugs(49, 3, HERE);
    Snmp::Request& req = static_cast<Snmp::Request&>(*request);
    req.pdu.command = SNMP_PDU_RESPONSE;
    req.pdu.errstat = error;
    u_char buffer[SNMP_REQUEST_SIZE];
    int len = sizeof(buffer);
    snmp_build(&req.session, &req.pdu, buffer, &len);
    comm_udp_sendto(fd, req.address, buffer, len);
}

void
Snmp::SendResponse(const Ipc::RequestId requestId, const Pdu &pdu)
{
    debugs(49, 5, HERE);
    // snmpAgentResponse() can modify arg
    Pdu tmp = pdu;
    Snmp::Response response(requestId);
    snmp_pdu* response_pdu = NULL;
    try {
        response_pdu = snmpAgentResponse(&tmp);
        Must(response_pdu != NULL);
        response.pdu = static_cast<Pdu&>(*response_pdu);
        snmp_free_pdu(response_pdu);
    } catch (const std::exception& e) {
        debugs(49, DBG_CRITICAL, HERE << e.what());
        response.pdu.command = SNMP_PDU_RESPONSE;
        response.pdu.errstat = SNMP_ERR_GENERR;
    }
    Ipc::TypedMsgHdr message;
    response.pack(message);
    Ipc::SendMessage(Ipc::Port::CoordinatorAddr(), message);
}

