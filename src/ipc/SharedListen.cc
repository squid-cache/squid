/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "config.h"
#include <map>
#include "comm.h"
#include "base/TextException.h"
#include "ipc/Port.h"
#include "ipc/Messages.h"
#include "ipc/Kids.h"
#include "ipc/TypedMsgHdr.h"
#include "ipc/StartListening.h"
#include "ipc/SharedListen.h"


/// holds information necessary to handle JoinListen response
class PendingOpenRequest
{
public:
    Ipc::OpenListenerParams params; ///< actual comm_open_sharedListen() parameters
    AsyncCall::Pointer callback; // who to notify
};

/// maps ID assigned at request time to the response callback
typedef std::map<int, PendingOpenRequest> SharedListenRequestMap;
static SharedListenRequestMap TheSharedListenRequestMap;

static int
AddToMap(const PendingOpenRequest &por)
{
    // find unused ID using linear seach; there should not be many entries
    for (int id = 0; true; ++id) {
        if (TheSharedListenRequestMap.find(id) == TheSharedListenRequestMap.end()) {
            TheSharedListenRequestMap[id] = por;
            return id;
        }
    }
    assert(false); // not reached
    return -1;
}

Ipc::OpenListenerParams::OpenListenerParams()
{
    xmemset(this, 0, sizeof(*this));
}

bool
Ipc::OpenListenerParams::operator <(const OpenListenerParams &p) const
{
    if (sock_type != p.sock_type)
        return sock_type < p.sock_type;

    if (proto != p.proto)
        return proto < p.proto;

    // ignore flags and fdNote differences because they do not affect binding

    return addr.compareWhole(p.addr) < 0;
}



Ipc::SharedListenRequest::SharedListenRequest(): requestorId(-1), mapId(-1)
{
    // caller will then set public data members
}

Ipc::SharedListenRequest::SharedListenRequest(const TypedMsgHdr &hdrMsg)
{
    hdrMsg.checkType(mtSharedListenRequest);
    hdrMsg.getPod(*this);
}

void Ipc::SharedListenRequest::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtSharedListenRequest);
    hdrMsg.putPod(*this);
}


Ipc::SharedListenResponse::SharedListenResponse(int aFd, int anErrNo, int aMapId):
        fd(aFd), errNo(anErrNo), mapId(aMapId)
{
}

Ipc::SharedListenResponse::SharedListenResponse(const TypedMsgHdr &hdrMsg):
        fd(-1), errNo(0), mapId(-1)
{
    hdrMsg.checkType(mtSharedListenResponse);
    hdrMsg.getPod(*this);
    fd = hdrMsg.getFd();
}

void Ipc::SharedListenResponse::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtSharedListenResponse);
    hdrMsg.putPod(*this);
    hdrMsg.putFd(fd);
}


void Ipc::JoinSharedListen(const OpenListenerParams &params,
                           AsyncCall::Pointer &callback)
{
    PendingOpenRequest por;
    por.params = params;
    por.callback = callback;

    SharedListenRequest request;
    request.requestorId = KidIdentifier;
    request.params = por.params;
    request.mapId = AddToMap(por);

    debugs(54, 3, HERE << "getting listening FD for " << request.params.addr <<
           " mapId=" << request.mapId);

    TypedMsgHdr message;
    request.pack(message);
    SendMessage(coordinatorAddr, message);
}

void Ipc::SharedListenJoined(const SharedListenResponse &response)
{
    const int fd = response.fd;

    debugs(54, 3, HERE << "got listening FD " << fd << " errNo=" <<
           response.errNo << " mapId=" << response.mapId);

    Must(TheSharedListenRequestMap.find(response.mapId) != TheSharedListenRequestMap.end());
    PendingOpenRequest por = TheSharedListenRequestMap[response.mapId];
    Must(por.callback != NULL);
    TheSharedListenRequestMap.erase(response.mapId);

    if (fd >= 0) {
        OpenListenerParams &p = por.params;
        struct addrinfo *AI = NULL;
        p.addr.GetAddrInfo(AI);
        AI->ai_socktype = p.sock_type;
        AI->ai_protocol = p.proto;
        comm_import_opened(fd, p.addr, p.flags, FdNote(p.fdNote), AI);
        p.addr.FreeAddrInfo(AI);
    }

    StartListeningCb *cbd =
        dynamic_cast<StartListeningCb*>(por.callback->getDialer());
    Must(cbd);
    cbd->fd = fd;
    cbd->errNo = response.errNo;
    ScheduleCallHere(por.callback);
}
