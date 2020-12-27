/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
    hdrMsg.checkType(mtFindStrand);
    hdrMsg.getPod(requestorId);
    hdrMsg.getString(tag);
}

void Ipc::StrandSearchRequest::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtFindStrand);
    hdrMsg.putPod(requestorId);
    hdrMsg.putString(tag);
}

Ipc::StrandSearchResponse::StrandSearchResponse(const bool isIndexed, const StrandCoord &aStrand):
    indexed(isIndexed),
    strand(aStrand)
{
}

Ipc::StrandSearchResponse::StrandSearchResponse(const TypedMsgHdr &hdrMsg):
    indexed(false)
{
    hdrMsg.checkType(mtStrandReady);
    hdrMsg.getPod(indexed);
    strand.unpack(hdrMsg);
}

void
Ipc::StrandSearchResponse::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandReady);
    hdrMsg.putPod(indexed);
    strand.pack(hdrMsg);
}

