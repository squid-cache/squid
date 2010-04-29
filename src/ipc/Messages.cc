/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "comm.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"


Ipc::StrandCoord::StrandCoord(): kidId(-1), pid(0)
{
}

Ipc::StrandCoord::StrandCoord(int aKidId, pid_t aPid): kidId(aKidId), pid(aPid)
{
}

Ipc::StrandCoord::StrandCoord(const TypedMsgHdr &hdrMsg): kidId(-1), pid(0)
{
	hdrMsg.getData(mtRegistration, this, sizeof(this));
}

void Ipc::StrandCoord::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.putData(mtRegistration, this, sizeof(this));
}
