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
#include "ipc/Messages.h"
#include "ipc/RequestId.h"
#include "ipc/TypedMsgHdr.h"
#include "snmp/Response.h"

Snmp::Response::Response(const Ipc::RequestId aRequestId):
    Ipc::Response(aRequestId), pdu()
{
}

Snmp::Response::Response(const Ipc::TypedMsgHdr &msg)
{
    msg.checkType(Ipc::mtSnmpResponse);
    msg.getPod(requestId);
    pdu.unpack(msg);
}

void
Snmp::Response::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtSnmpResponse);
    msg.putPod(requestId);
    pdu.pack(msg);
}

Ipc::Response::Pointer
Snmp::Response::clone() const
{
    return new Response(*this);
}

