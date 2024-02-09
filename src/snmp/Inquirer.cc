/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "CommCalls.h"
#include "ipc/UdsOp.h"
#include "snmp/Inquirer.h"
#include "snmp/Request.h"
#include "snmp/Response.h"
#include "snmp_core.h"

CBDATA_NAMESPACED_CLASS_INIT(Snmp, Inquirer);

Snmp::Inquirer::Inquirer(const Request& aRequest, const Ipc::StrandCoords& coords):
    Ipc::Inquirer(aRequest.clone(), coords, 2),
    aggrPdu(aRequest.pdu)
{
    conn = new Comm::Connection;
    conn->fd = aRequest.fd;
    ImportFdIntoComm(conn, SOCK_DGRAM, IPPROTO_UDP, Ipc::fdnInSnmpSocket);

    debugs(49, 5, MYNAME);
    closer = asyncCall(49, 5, "Snmp::Inquirer::noteCommClosed",
                       CommCbMemFunT<Inquirer, CommCloseCbParams>(this, &Inquirer::noteCommClosed));
    comm_add_close_handler(conn->fd, closer);

    // forget client FD to avoid sending it to strands that may forget to close
    if (Request *snmpRequest = dynamic_cast<Request*>(request.getRaw()))
        snmpRequest->fd = -1;
}

/// closes our copy of the client connection socket
void
Snmp::Inquirer::cleanup()
{
    if (Comm::IsConnOpen(conn)) {
        if (closer != nullptr) {
            comm_remove_close_handler(conn->fd, closer);
            closer = nullptr;
        }
        conn->close();
    }
    conn = nullptr;
}

void
Snmp::Inquirer::start()
{
    debugs(49, 5, MYNAME);
    Ipc::Inquirer::start();
    Must(Comm::IsConnOpen(conn));
    inquire();
}

void
Snmp::Inquirer::handleException(const std::exception& e)
{
    aggrPdu.errstat = SNMP_ERR_GENERR;
    Ipc::Inquirer::handleException(e);
}

bool
Snmp::Inquirer::aggregate(Response::Pointer aResponse)
{
    Snmp::Response& response = static_cast<Snmp::Response&>(*aResponse);
    bool error = response.pdu.errstat != SNMP_ERR_NOERROR;
    if (error) {
        aggrPdu = response.pdu;
    } else {
        aggrPdu.aggregate(response.pdu);
    }
    return !error;
}

/// called when the some external force closed our socket
void
Snmp::Inquirer::noteCommClosed(const CommCloseCbParams& params)
{
    debugs(49, 5, MYNAME);
    Must(!Comm::IsConnOpen(conn) || conn->fd == params.conn->fd);
    closer = nullptr;
    if (conn) {
        conn->noteClosure();
        conn = nullptr;
    }
    mustStop("commClosed");
}

bool
Snmp::Inquirer::doneAll() const
{
    return !writer && Ipc::Inquirer::doneAll();
}

void
Snmp::Inquirer::sendResponse()
{
    debugs(49, 5, MYNAME);

    if (!Comm::IsConnOpen(conn))
        return; // client gone

    aggrPdu.fixAggregate();
    aggrPdu.command = SNMP_PDU_RESPONSE;
    u_char buffer[SNMP_REQUEST_SIZE];
    int len = sizeof(buffer);
    Snmp::Request& req = static_cast<Snmp::Request&>(*request);
    snmp_build(&req.session, &aggrPdu, buffer, &len);
    comm_udp_sendto(conn->fd, req.address, buffer, len);
}

