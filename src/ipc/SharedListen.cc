/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/TextException.h"
#include "comm.h"
#include "comm/Connection.h"
#include "globals.h"
#include "ipc/Kids.h"
#include "ipc/Messages.h"
#include "ipc/Port.h"
#include "ipc/SharedListen.h"
#include "ipc/StartListening.h"
#include "ipc/TypedMsgHdr.h"
#include "tools.h"

#include <list>
#include <map>

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

/// accumulates delayed requests until they are ready to be sent, in FIFO order
typedef std::list<PendingOpenRequest> DelayedSharedListenRequests;
static DelayedSharedListenRequests TheDelayedRequests;

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
    memset(this, 0, sizeof(*this));
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
    // other conn details are passed in OpenListenerParams and filled out by SharedListenJoin()
}

void Ipc::SharedListenResponse::pack(TypedMsgHdr &hdrMsg) const
{
    hdrMsg.setType(mtSharedListenResponse);
    hdrMsg.putPod(*this);
    hdrMsg.putFd(fd);
}

static void
SendSharedListenRequest(const PendingOpenRequest &por)
{
    Ipc::SharedListenRequest request;
    request.requestorId = KidIdentifier;
    request.params = por.params;
    request.mapId = AddToMap(por);

    debugs(54, 3, "getting listening FD for " << request.params.addr <<
           " mapId=" << request.mapId);

    Ipc::TypedMsgHdr message;
    request.pack(message);
    SendMessage(Ipc::Port::CoordinatorAddr(), message);
}

static void
kickDelayedRequest()
{
    if (TheDelayedRequests.empty())
        return; // no pending requests to resume

    debugs(54, 3, "resuming with " << TheSharedListenRequestMap.size() <<
           " active + " << TheDelayedRequests.size() << " delayed requests");

    SendSharedListenRequest(*TheDelayedRequests.begin());
    TheDelayedRequests.pop_front();
}

void
Ipc::JoinSharedListen(const OpenListenerParams &params, AsyncCall::Pointer &cb)
{
    PendingOpenRequest por;
    por.params = params;
    por.callback = cb;

    const DelayedSharedListenRequests::size_type concurrencyLimit = 1;
    if (TheSharedListenRequestMap.size() >= concurrencyLimit) {
        debugs(54, 3, "waiting for " << TheSharedListenRequestMap.size() <<
               " active + " << TheDelayedRequests.size() << " delayed requests");
        TheDelayedRequests.push_back(por);
    } else {
        SendSharedListenRequest(por);
    }
}

void Ipc::SharedListenJoined(const SharedListenResponse &response)
{
    // Dont debugs c fully since only FD is filled right now.
    debugs(54, 3, "got listening FD " << response.fd << " errNo=" <<
           response.errNo << " mapId=" << response.mapId << " with " <<
           TheSharedListenRequestMap.size() << " active + " <<
           TheDelayedRequests.size() << " delayed requests");

    Must(TheSharedListenRequestMap.find(response.mapId) != TheSharedListenRequestMap.end());
    PendingOpenRequest por = TheSharedListenRequestMap[response.mapId];
    Must(por.callback != NULL);
    TheSharedListenRequestMap.erase(response.mapId);

    StartListeningCb *cbd = dynamic_cast<StartListeningCb*>(por.callback->getDialer());
    assert(cbd && cbd->conn != NULL);
    Must(cbd && cbd->conn != NULL);
    cbd->conn->fd = response.fd;

    if (Comm::IsConnOpen(cbd->conn)) {
        OpenListenerParams &p = por.params;
        cbd->conn->local = p.addr;
        cbd->conn->flags = p.flags;
        // XXX: leave the comm AI stuff to comm_import_opened()?
        struct addrinfo *AI = NULL;
        p.addr.getAddrInfo(AI);
        AI->ai_socktype = p.sock_type;
        AI->ai_protocol = p.proto;
        comm_import_opened(cbd->conn, FdNote(p.fdNote), AI);
        Ip::Address::FreeAddr(AI);
    }

    cbd->errNo = response.errNo;
    cbd->handlerSubscription = por.params.handlerSubscription;
    ScheduleCallHere(por.callback);

    kickDelayedRequest();
}

