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


Ipc::StrandSearchRequest::StrandSearchRequest(): requestorId(-1), data(0)
{
}

Ipc::StrandSearchRequest::StrandSearchRequest(const TypedMsgHdr &hdrMsg):
    requestorId(-1), data(NULL)
{
    hdrMsg.checkType(mtStrandSearchRequest);
    hdrMsg.getPod(requestorId);
    hdrMsg.getPod(data);
    hdrMsg.getString(tag);
}

void Ipc::StrandSearchRequest::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandSearchRequest);
    hdrMsg.putPod(requestorId);
    hdrMsg.putPod(data);
    hdrMsg.putString(tag);
}


/* StrandSearchResponse */

Ipc::StrandSearchResponse::StrandSearchResponse(void *const aData,
    const Ipc::StrandCoord &aStrand):
    data(aData), strand(aStrand)
{
}

Ipc::StrandSearchResponse::StrandSearchResponse(const TypedMsgHdr &hdrMsg):
    data(NULL)
{
    hdrMsg.checkType(mtStrandSearchResponse);
    hdrMsg.getPod(data);
    strand.unpack(hdrMsg);
}

void Ipc::StrandSearchResponse::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtStrandSearchResponse);
    hdrMsg.putPod(data);
    strand.pack(hdrMsg);
}
