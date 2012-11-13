/*
 * DEBUG: section 49    SNMP Interface
 *
 */

#include "squid.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp/Request.h"

Snmp::Request::Request(int aRequestorId, unsigned int aRequestId,
                       const Pdu& aPdu, const Session& aSession,
                       int aFd, const Ip::Address& anAddress):
        Ipc::Request(aRequestorId, aRequestId),
        pdu(aPdu), session(aSession), fd(aFd), address(anAddress)
{
}

Snmp::Request::Request(const Request& request):
        Ipc::Request(request.requestorId, request.requestId),
        pdu(request.pdu), session(request.session),
        fd(request.fd), address(request.address)
{
}

Snmp::Request::Request(const Ipc::TypedMsgHdr& msg):
        Ipc::Request(0, 0)
{
    msg.checkType(Ipc::mtSnmpRequest);
    msg.getPod(requestorId);
    msg.getPod(requestId);
    pdu.unpack(msg);
    session.unpack(msg);
    msg.getPod(address);

    fd = msg.getFd();
}

void
Snmp::Request::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtSnmpRequest);
    msg.putPod(requestorId);
    msg.putPod(requestId);
    pdu.pack(msg);
    session.pack(msg);
    msg.putPod(address);

    msg.putFd(fd);
}

Ipc::Request::Pointer
Snmp::Request::clone() const
{
    return new Request(*this);
}
