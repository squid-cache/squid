/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "Debug.h"
#include "globals.h"
#include "ipc/Port.h"
#include "ipc/StrandCoord.h"
#include "ipc/TypedMsgHdr.h"

Ipc::StrandCoord::StrandCoord(): kidId(-1), pid(0)
{
}

Ipc::StrandCoord::StrandCoord(int aKidId, pid_t aPid): kidId(aKidId), pid(aPid)
{
}

void
Ipc::StrandCoord::unpack(const TypedMsgHdr &hdrMsg)
{
    hdrMsg.getPod(kidId);
    hdrMsg.getPod(pid);
    hdrMsg.getString(tag);
}

void Ipc::StrandCoord::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.putPod(kidId);
    hdrMsg.putPod(pid);
    hdrMsg.putString(tag);
}

Ipc::StrandMessage::StrandMessage(const Ipc::MessageType msgType, const StrandCoord &aStrand):
    messageType(msgType),
    strand(aStrand)
{
}

Ipc::StrandMessage::StrandMessage(const TypedMsgHdr &hdrMsg):
    messageType(hdrMsg.type<Ipc::MessageType>())
{
    strand.unpack(hdrMsg);
}

void
Ipc::StrandMessage::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(messageType);
    strand.pack(hdrMsg);
}

void
Ipc::StrandMessage::NotifyCoordinator(const Ipc::MessageType msgType, const char *tag)
{
    static const auto pid = getpid();
    Ipc::StrandMessage message(msgType, Ipc::StrandCoord(KidIdentifier, pid));
    if (tag)
        message.strand.tag = tag;
    Ipc::TypedMsgHdr hdr;
    message.pack(hdr);
    SendMessage(Ipc::Port::CoordinatorAddr(), hdr);
}

