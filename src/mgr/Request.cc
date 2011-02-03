/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionParams.h"
#include "mgr/Request.h"


Mgr::Request::Request(int aRequestorId, unsigned int aRequestId, int aFd,
                      const ActionParams &aParams):
        Ipc::Request(aRequestorId, aRequestId),
        fd(aFd), params(aParams)
{
    Must(requestorId > 0);
}

Mgr::Request::Request(const Request& request):
        Ipc::Request(request.requestorId, request.requestId),
        fd(request.fd), params(request.params)
{
}

Mgr::Request::Request(const Ipc::TypedMsgHdr& msg):
        Ipc::Request(0, 0)
{
    msg.checkType(Ipc::mtCacheMgrRequest);
    msg.getPod(requestorId);
    msg.getPod(requestId);
    params = ActionParams(msg);

    fd = msg.getFd();
}

void
Mgr::Request::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrRequest);
    msg.putPod(requestorId);
    msg.putPod(requestId);
    params.pack(msg);

    msg.putFd(fd);
}

Ipc::Request::Pointer
Mgr::Request::clone() const
{
    return new Request(*this);
}
