/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "ipc/Messages.h"
#include "ipc/StrandSearch.h"
#include "ipc/TypedMsgHdr.h"


Ipc::StrandSearchRequest::StrandSearchRequest(): requestorId(-1), requestId(0)
{
}

Ipc::StrandSearchRequest::StrandSearchRequest(const TypedMsgHdr &hdrMsg):
    requestorId(-1), requestId(0)
{
    hdrMsg.checkType(mtStrandSearchRequest);
    hdrMsg.getPod(requestorId);
    hdrMsg.getPod(requestId);
    hdrMsg.getString(tag);
}

void Ipc::StrandSearchRequest::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandSearchRequest);
    hdrMsg.putPod(requestorId);
    hdrMsg.putPod(requestId);
    hdrMsg.putString(tag);
}


/* StrandSearchResponse */

Ipc::StrandSearchResponse::StrandSearchResponse(int aRequestId,
    const Ipc::StrandCoord &aStrand):
    requestId(aRequestId), strand(aStrand)
{
}

Ipc::StrandSearchResponse::StrandSearchResponse(const TypedMsgHdr &hdrMsg):
    requestId(0)
{
    hdrMsg.checkType(mtStrandSearchResponse);
    hdrMsg.getPod(requestId);
    strand.unpack(hdrMsg);
}

void Ipc::StrandSearchResponse::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandSearchResponse);
    hdrMsg.putPod(requestId);
    strand.pack(hdrMsg);
}
