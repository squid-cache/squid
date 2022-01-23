/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "globals.h"
#include "ipc/Messages.h"
#include "ipc/StrandSearch.h"
#include "ipc/TypedMsgHdr.h"

Ipc::StrandSearchRequest::StrandSearchRequest(const String &aTag):
    requestorId(KidIdentifier),
    tag(aTag),
    qid(MyQuestionerId())
{
}

Ipc::StrandSearchRequest::StrandSearchRequest(const TypedMsgHdr &hdrMsg):
    requestorId(-1)
{
    hdrMsg.checkType(mtFindStrand);
    hdrMsg.getPod(requestorId);
    hdrMsg.getString(tag);
    qid.unpack(hdrMsg);
}

void Ipc::StrandSearchRequest::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtFindStrand);
    hdrMsg.putPod(requestorId);
    hdrMsg.putString(tag);
    qid.pack(hdrMsg);
}

