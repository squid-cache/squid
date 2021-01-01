/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/Messages.h"
#include "ipc/StrandSearch.h"
#include "ipc/TypedMsgHdr.h"

Ipc::StrandSearchRequest::StrandSearchRequest(): requestorId(-1)
{
}

Ipc::StrandSearchRequest::StrandSearchRequest(const TypedMsgHdr &hdrMsg):
    requestorId(-1)
{
    hdrMsg.checkType(mtStrandSearchRequest);
    hdrMsg.getPod(requestorId);
    hdrMsg.getString(tag);
}

void Ipc::StrandSearchRequest::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandSearchRequest);
    hdrMsg.putPod(requestorId);
    hdrMsg.putString(tag);
}

/* StrandSearchResponse */

Ipc::StrandSearchResponse::StrandSearchResponse(const Ipc::StrandCoord &aStrand):
    strand(aStrand)
{
}

Ipc::StrandSearchResponse::StrandSearchResponse(const TypedMsgHdr &hdrMsg)
{
    hdrMsg.checkType(mtStrandSearchResponse);
    strand.unpack(hdrMsg);
}

void Ipc::StrandSearchResponse::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandSearchResponse);
    strand.pack(hdrMsg);
}

