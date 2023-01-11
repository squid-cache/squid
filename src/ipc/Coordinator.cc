/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "base/Subscription.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "comm.h"
#include "comm/Connection.h"
#include "ipc/Coordinator.h"
#include "ipc/SharedListen.h"
#include "mgr/Inquirer.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "tools.h"
#if SQUID_SNMP
#include "snmp/Inquirer.h"
#include "snmp/Request.h"
#include "snmp/Response.h"
#endif

#include <cerrno>

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Coordinator);
Ipc::Coordinator* Ipc::Coordinator::TheInstance = NULL;

Ipc::Coordinator::Coordinator():
    Port(Ipc::Port::CoordinatorAddr())
{
}

void Ipc::Coordinator::start()
{
    Port::start();
}

Ipc::StrandCoord* Ipc::Coordinator::findStrand(int kidId)
{
    typedef StrandCoords::iterator SI;
    for (SI iter = strands_.begin(); iter != strands_.end(); ++iter) {
        if (iter->kidId == kidId)
            return &(*iter);
    }
    return NULL;
}

void Ipc::Coordinator::registerStrand(const StrandCoord& strand)
{
    debugs(54, 3, HERE << "registering kid" << strand.kidId <<
           ' ' << strand.tag);
    if (StrandCoord* found = findStrand(strand.kidId)) {
        const String oldTag = found->tag;
        *found = strand;
        if (oldTag.size() && !strand.tag.size())
            found->tag = oldTag; // keep more detailed info (XXX?)
    } else {
        strands_.push_back(strand);
    }

    // notify searchers waiting for this new strand, if any
    typedef Searchers::iterator SRI;
    for (SRI i = searchers.begin(); i != searchers.end();) {
        if (i->tag == strand.tag) {
            notifySearcher(*i, strand);
            i = searchers.erase(i);
        } else {
            ++i;
        }
    }
}

void Ipc::Coordinator::receive(const TypedMsgHdr& message)
{
    switch (message.rawType()) {
    case mtRegisterStrand:
        debugs(54, 6, HERE << "Registration request");
        handleRegistrationRequest(StrandMessage(message));
        break;

    case mtFindStrand: {
        const StrandSearchRequest sr(message);
        debugs(54, 6, HERE << "Strand search request: " << sr.requestorId <<
               " tag: " << sr.tag);
        handleSearchRequest(sr);
        break;
    }

    case mtSharedListenRequest:
        debugs(54, 6, HERE << "Shared listen request");
        handleSharedListenRequest(SharedListenRequest(message));
        break;

    case mtCacheMgrRequest: {
        debugs(54, 6, HERE << "Cache manager request");
        const Mgr::Request req(message);
        handleCacheMgrRequest(req);
    }
    break;

    case mtCacheMgrResponse: {
        debugs(54, 6, HERE << "Cache manager response");
        const Mgr::Response resp(message);
        handleCacheMgrResponse(Mine(resp));
    }
    break;

#if SQUID_SNMP
    case mtSnmpRequest: {
        debugs(54, 6, HERE << "SNMP request");
        const Snmp::Request req(message);
        handleSnmpRequest(req);
    }
    break;

    case mtSnmpResponse: {
        debugs(54, 6, HERE << "SNMP response");
        const Snmp::Response resp(message);
        handleSnmpResponse(Mine(resp));
    }
    break;
#endif

    default:
        Port::receive(message);
        break;
    }
}

void Ipc::Coordinator::handleRegistrationRequest(const StrandMessage& msg)
{
    registerStrand(msg.strand);

    // send back an acknowledgement; TODO: remove as not needed?
    TypedMsgHdr message;
    msg.pack(mtStrandRegistered, message);
    SendMessage(MakeAddr(strandAddrLabel, msg.strand.kidId), message);
}

void
Ipc::Coordinator::handleSharedListenRequest(const SharedListenRequest& request)
{
    debugs(54, 4, HERE << "kid" << request.requestorId <<
           " needs shared listen FD for " << request.params.addr);
    Listeners::const_iterator i = listeners.find(request.params);
    int errNo = 0;
    const Comm::ConnectionPointer c = (i != listeners.end()) ?
                                      i->second : openListenSocket(request, errNo);

    debugs(54, 3, HERE << "sending shared listen " << c << " for " <<
           request.params.addr << " to kid" << request.requestorId <<
           " mapId=" << request.mapId);

    SharedListenResponse response(c->fd, errNo, request.mapId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrLabel, request.requestorId), message);
}

void
Ipc::Coordinator::handleCacheMgrRequest(const Mgr::Request& request)
{
    debugs(54, 4, HERE);

    try {
        Mgr::Action::Pointer action =
            CacheManager::GetInstance()->createRequestedAction(request.params);
        AsyncJob::Start(new Mgr::Inquirer(action, request, strands_));
    } catch (const std::exception &ex) {
        debugs(54, DBG_IMPORTANT, "BUG: cannot aggregate mgr:" <<
               request.params.actionName << ": " << ex.what());
        // TODO: Avoid half-baked Connections or teach them how to close.
        ::close(request.conn->fd);
        request.conn->fd = -1;
        return; // the worker will timeout and close
    }

    // Let the strand know that we are now responsible for handling the request
    Mgr::Response response(request.requestId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrLabel, request.requestorId), message);

}

void
Ipc::Coordinator::handleCacheMgrResponse(const Mgr::Response& response)
{
    Mgr::Inquirer::HandleRemoteAck(response);
}

void
Ipc::Coordinator::handleSearchRequest(const Ipc::StrandSearchRequest &request)
{
    // do we know of a strand with the given search tag?
    const StrandCoord *strand = NULL;
    typedef StrandCoords::const_iterator SCCI;
    for (SCCI i = strands_.begin(); !strand && i != strands_.end(); ++i) {
        if (i->tag == request.tag)
            strand = &(*i);
    }

    if (strand) {
        notifySearcher(request, *strand);
        return;
    }

    searchers.push_back(request);
    debugs(54, 3, HERE << "cannot yet tell kid" << request.requestorId <<
           " who " << request.tag << " is");
}

void
Ipc::Coordinator::notifySearcher(const Ipc::StrandSearchRequest &request,
                                 const StrandCoord& strand)
{
    debugs(54, 3, HERE << "tell kid" << request.requestorId << " that " <<
           request.tag << " is kid" << strand.kidId);
    const StrandMessage response(strand, request.qid);
    TypedMsgHdr message;
    response.pack(mtStrandReady, message);
    SendMessage(MakeAddr(strandAddrLabel, request.requestorId), message);
}

#if SQUID_SNMP
void
Ipc::Coordinator::handleSnmpRequest(const Snmp::Request& request)
{
    debugs(54, 4, HERE);

    Snmp::Response response(request.requestId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrLabel, request.requestorId), message);

    AsyncJob::Start(new Snmp::Inquirer(request, strands_));
}

void
Ipc::Coordinator::handleSnmpResponse(const Snmp::Response& response)
{
    debugs(54, 4, HERE);
    Snmp::Inquirer::HandleRemoteAck(response);
}
#endif

Comm::ConnectionPointer
Ipc::Coordinator::openListenSocket(const SharedListenRequest& request,
                                   int &errNo)
{
    const OpenListenerParams &p = request.params;

    debugs(54, 6, HERE << "opening listen FD at " << p.addr << " for kid" <<
           request.requestorId);

    Comm::ConnectionPointer newConn = new Comm::Connection;
    newConn->local = p.addr; // comm_open_listener may modify it
    newConn->flags = p.flags;

    enter_suid();
    comm_open_listener(p.sock_type, p.proto, newConn, FdNote(p.fdNote));
    errNo = Comm::IsConnOpen(newConn) ? 0 : errno;
    leave_suid();

    debugs(54, 6, HERE << "tried listening on " << newConn << " for kid" <<
           request.requestorId);

    // cache positive results
    if (Comm::IsConnOpen(newConn))
        listeners[request.params] = newConn;

    return newConn;
}

void Ipc::Coordinator::broadcastSignal(int sig) const
{
    typedef StrandCoords::const_iterator SCI;
    for (SCI iter = strands_.begin(); iter != strands_.end(); ++iter) {
        debugs(54, 5, HERE << "signal " << sig << " to kid" << iter->kidId <<
               ", PID=" << iter->pid);
        kill(iter->pid, sig);
    }
}

Ipc::Coordinator* Ipc::Coordinator::Instance()
{
    if (!TheInstance)
        TheInstance = new Coordinator;
    // XXX: if the Coordinator job quits, this pointer will become invalid
    // we could make Coordinator death fatal, except during exit, but since
    // Strands do not re-register, even process death would be pointless.
    return TheInstance;
}

const Ipc::StrandCoords&
Ipc::Coordinator::strands() const
{
    return strands_;
}

