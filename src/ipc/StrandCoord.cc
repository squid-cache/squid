/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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

Ipc::StrandMessage::StrandMessage(const StrandCoord &aStrand, const QuestionerId aQid):
    strand(aStrand),
    qid(aQid)
{
}

Ipc::StrandMessage::StrandMessage(const TypedMsgHdr &hdrMsg)
{
    strand.unpack(hdrMsg);
    qid.unpack(hdrMsg);
}

void
Ipc::StrandMessage::pack(const MessageType messageType, TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(messageType);
    strand.pack(hdrMsg);
    qid.pack(hdrMsg);
}

void
Ipc::StrandMessage::NotifyCoordinator(const MessageType msgType, const char *tag)
{
    static const auto pid = getpid();
    StrandMessage message(StrandCoord(KidIdentifier, pid), MyQuestionerId());
    if (tag)
        message.strand.tag = tag;
    TypedMsgHdr hdr;
    message.pack(msgType, hdr);
    SendMessage(Port::CoordinatorAddr(), hdr);
}

