/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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

#include <algorithm>
#include <cerrno>

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Coordinator);
Ipc::Coordinator* Ipc::Coordinator::TheInstance = NULL;

static Ipc::StrandCoords
ToStrandCoords(const Ipc::Coordinator::QuestionerCoords &questionerCoords)
{
    Ipc::StrandCoords coords;
    for (const auto p: questionerCoords)
        coords.push_back(p.second);
    return coords;
}

Ipc::Coordinator::Coordinator():
    Port(Ipc::Port::CoordinatorAddr())
{
}

void Ipc::Coordinator::start()
{
    Port::start();
}

void Ipc::Coordinator::registerStrand(const StrandMessage& msg)
{
    const auto &strand = msg.strand;
    debugs(54, 3, HERE << "registering kid" << strand.kidId <<
           ' ' << strand.tag);
    auto registered = std::find_if(strands_.begin(), strands_.end(),
    [&strand](const QuestionerCoord &coord) { return coord.second.kidId == strand.kidId; });
    if (registered != strands_.end()) {
        const auto oldTag = registered->second.tag;
        registered->second = strand;
        if (oldTag.size() && !strand.tag.size())
            registered->second.tag = oldTag; // keep more detailed info (XXX?)
    } else {
        strands_.emplace_back(msg.qid, strand);
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

    case mtForegroundRebuild:
        debugs(54, 6, "Foreground rebuild message");
        handleForegroundRebuildMessage(StrandMessage(message));
        break;

    case mtRebuildFinished:
        debugs(54, 6, "Rebuild finished message");
        handleRebuildFinishedMessage(StrandMessage(message));
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
    registerStrand(msg);

    // send back an acknowledgement; TODO: remove as not needed?
    TypedMsgHdr message;
    msg.pack(mtStrandRegistered, message);
    SendMessage(MakeAddr(strandAddrLabel, msg.strand.kidId), message);
}

void
Ipc::Coordinator::handleForegroundRebuildMessage(const StrandMessage& msg)
{
    // notify any searchers waiting for this strand
    for (const auto &searchRequest: searchers) {
        if (searchRequest.tag != msg.strand.tag)
            continue;

        StrandMessage response(msg.strand, searchRequest.qid);
        TypedMsgHdr message;
        response.pack(mtStrandBusy, message);
        SendMessage(MakeAddr(strandAddrLabel, searchRequest.requestorId), message);
    }
}

void
Ipc::Coordinator::handleRebuildFinishedMessage(const StrandMessage& msg)
{
    const auto alreadyFinished = std::find_if(rebuildFinishedStrands_.begin(), rebuildFinishedStrands_.end(),
    [&msg](const StrandCoord &coord) { return msg.strand.kidId == coord.kidId; });
    if (alreadyFinished != rebuildFinishedStrands_.end()) {
        // A message from a possibly restarted disker.
        // Do not notify other strands the second time, only refresh the coord.
        *alreadyFinished = msg.strand;
        return;
    }
    rebuildFinishedStrands_.push_back(msg.strand);

    const auto alreadyTagged = std::find_if(strands_.begin(), strands_.end(),
    [&msg](const QuestionerCoord &coord) { return msg.strand.tag == coord.second.tag; });

    if (alreadyTagged == strands_.end()) {
        debugs(54, 3, "waiting for kid" << msg.strand.kidId << " tag to broadcast that it is indexed");
        return;
    }

    // notify all existing strands, new strands will be notified in notifySearcher()
    for (const auto &strand: strands_) {
        debugs(54, 3, "tell kid" << strand.second.kidId << " that kid" << msg.strand.kidId << " is indexed");
        StrandReady response(msg.strand, strand.first, true);
        TypedMsgHdr message;
        response.pack(message);
        SendMessage(MakeAddr(strandAddrLabel, strand.second.kidId), message);
    }
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
        AsyncJob::Start(new Mgr::Inquirer(action, request, ToStrandCoords(strands_)));
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
    const auto alreadyTagged = std::find_if(strands_.begin(), strands_.end(),
    [&request](const QuestionerCoord &coord) { return request.tag == coord.second.tag; });

    if (alreadyTagged != strands_.end()) {
        notifySearcher(request, alreadyTagged->second);
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
    const auto isIndexed = std::find_if(rebuildFinishedStrands_.begin(), rebuildFinishedStrands_.end(),
    [&strand](const StrandCoord &coord) { return strand.kidId == coord.kidId; }) != rebuildFinishedStrands_.end();

    debugs(54, 3, "tell kid" << request.requestorId << " that " <<
           request.tag << " is kid" << strand.kidId << " (indexed:" << isIndexed << ")");

    const StrandReady response(strand, request.qid, isIndexed);
    TypedMsgHdr message;
    response.pack(message);
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

    AsyncJob::Start(new Snmp::Inquirer(request, ToStrandCoords(strands_)));
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

Ipc::Coordinator* Ipc::Coordinator::Instance()
{
    if (!TheInstance)
        TheInstance = new Coordinator;
    // XXX: if the Coordinator job quits, this pointer will become invalid
    // we could make Coordinator death fatal, except during exit, but since
    // Strands do not re-register, even process death would be pointless.
    return TheInstance;
}

