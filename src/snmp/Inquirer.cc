/*
 * $Id$
 *
 * DEBUG: section 49    SNMP Interface
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "CommCalls.h"
#include "ipc/UdsOp.h"
#include "snmp_core.h"
#include "snmp/Inquirer.h"
#include "snmp/Response.h"
#include "snmp/Request.h"


CBDATA_NAMESPACED_CLASS_INIT(Snmp, Inquirer);


Snmp::Inquirer::Inquirer(const Request& aRequest, const Ipc::StrandCoords& coords):
        Ipc::Inquirer(aRequest.clone(), coords, 2),
        aggrPdu(aRequest.pdu),
        fd(ImportFdIntoComm(aRequest.fd, SOCK_DGRAM, IPPROTO_UDP, Ipc::fdnInSnmpSocket))
{
    debugs(49, 5, HERE);
    closer = asyncCall(49, 5, "Snmp::Inquirer::noteCommClosed",
                       CommCbMemFunT<Inquirer, CommCloseCbParams>(this, &Inquirer::noteCommClosed));
    comm_add_close_handler(fd, closer);
}

/// closes our copy of the client connection socket
void
Snmp::Inquirer::cleanup()
{
    if (fd >= 0) {
        if (closer != NULL) {
            comm_remove_close_handler(fd, closer);
            closer = NULL;
        }
        comm_close(fd);
        fd = -1;
    }
}

void
Snmp::Inquirer::start()
{
    debugs(49, 5, HERE);
    Ipc::Inquirer::start();
    Must(fd >= 0);
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
    debugs(49, 5, HERE);
    Must(fd < 0 || fd == params.fd);
    fd = -1;
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
    debugs(49, 5, HERE);
    aggrPdu.fixAggregate();
    aggrPdu.command = SNMP_PDU_RESPONSE;
    u_char buffer[SNMP_REQUEST_SIZE];
    int len = sizeof(buffer);
    Snmp::Request& req = static_cast<Snmp::Request&>(*request);
    snmp_build(&req.session, &aggrPdu, buffer, &len);
    comm_udp_sendto(fd, req.address, buffer, len);
}
