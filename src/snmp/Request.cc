/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

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

    // Requests from strands have FDs. Requests from Coordinator do not.
    fd = msg.hasFd() ? msg.getFd() : -1;
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

    // Requests sent to Coordinator have FDs. Requests sent to strands do not.
    if (fd >= 0)
        msg.putFd(fd);
}

Ipc::Request::Pointer
Snmp::Request::clone() const
{
    return new Request(*this);
}

