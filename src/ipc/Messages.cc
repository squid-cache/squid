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


Ipc::Descriptor::Descriptor(): fromKid(-1), fd(-1)
{
}

Ipc::Descriptor::Descriptor(int aFromKid, int aFd): fromKid(aFromKid), fd(aFd)
{
}

Ipc::Descriptor::Descriptor(const TypedMsgHdr &hdrMsg): fromKid(-1), fd(-1)
{
    if (hdrMsg.type() == mtDescriptorGet) {
        hdrMsg.getData(mtDescriptorGet, this, sizeof(this));
        fd = -1;
    } else {
        hdrMsg.getData(mtDescriptorPut, this, sizeof(this));
        fd = hdrMsg.getFd();
    }
}

void Ipc::Descriptor::pack(TypedMsgHdr &hdrMsg) const
{
    if (fd >= 0) {
        hdrMsg.putData(mtDescriptorPut, this, sizeof(this));
        hdrMsg.putFd(fd);
    } else {
        hdrMsg.putData(mtDescriptorGet, this, sizeof(this));
    }
}
