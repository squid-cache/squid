/*
 * $Id$
 *
 * DEBUG: section 54    Interprocess Communication
 *
 */


#include "config.h"
#include "base/TextException.h"
#include "CacheManager.h"
#include "comm.h"
#include "ipc/Coordinator.h"
#include "ipc/SharedListen.h"
#include "mgr/Inquirer.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#if SQUID_SNMP
#include "snmp/Inquirer.h"
#include "snmp/Request.h"
#include "snmp/Response.h"
#endif

CBDATA_NAMESPACED_CLASS_INIT(Ipc, Coordinator);
Ipc::Coordinator* Ipc::Coordinator::TheInstance = NULL;


Ipc::Coordinator::Coordinator():
        Port(coordinatorAddr)
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
    if (StrandCoord* found = findStrand(strand.kidId))
        *found = strand;
    else
        strands_.push_back(strand);
}

void Ipc::Coordinator::receive(const TypedMsgHdr& message)
{
    switch (message.type()) {
    case mtRegistration:
        debugs(54, 6, HERE << "Registration request");
        handleRegistrationRequest(StrandCoord(message));
        break;

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
        handleCacheMgrResponse(resp);
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
        handleSnmpResponse(resp);
    }
    break;
#endif

    default:
        debugs(54, 1, HERE << "Unhandled message type: " << message.type());
        break;
    }
}

void Ipc::Coordinator::handleRegistrationRequest(const StrandCoord& strand)
{
    registerStrand(strand);

    // send back an acknowledgement; TODO: remove as not needed?
    TypedMsgHdr message;
    strand.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, strand.kidId), message);
}

void
Ipc::Coordinator::handleSharedListenRequest(const SharedListenRequest& request)
{
    debugs(54, 4, HERE << "kid" << request.requestorId <<
           " needs shared listen FD for " << request.params.addr);
    Listeners::const_iterator i = listeners.find(request.params);
    int errNo = 0;
    const int sock = (i != listeners.end()) ?
                     i->second : openListenSocket(request, errNo);

    debugs(54, 3, HERE << "sending shared listen FD " << sock << " for " <<
           request.params.addr << " to kid" << request.requestorId <<
           " mapId=" << request.mapId);

    SharedListenResponse response(sock, errNo, request.mapId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, request.requestorId), message);
}

void
Ipc::Coordinator::handleCacheMgrRequest(const Mgr::Request& request)
{
    debugs(54, 4, HERE);

    // Let the strand know that we are now responsible for handling the request
    Mgr::Response response(request.requestId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, request.requestorId), message);

    Mgr::Action::Pointer action =
        CacheManager::GetInstance()->createRequestedAction(request.params);
    AsyncJob::Start(new Mgr::Inquirer(action, request, strands_));
}

void
Ipc::Coordinator::handleCacheMgrResponse(const Mgr::Response& response)
{
    Mgr::Inquirer::HandleRemoteAck(response);
}

#if SQUID_SNMP
void
Ipc::Coordinator::handleSnmpRequest(const Snmp::Request& request)
{
    debugs(54, 4, HERE);

    Snmp::Response response(request.requestId);
    TypedMsgHdr message;
    response.pack(message);
    SendMessage(MakeAddr(strandAddrPfx, request.requestorId), message);

    AsyncJob::Start(new Snmp::Inquirer(request, strands_));
}

void
Ipc::Coordinator::handleSnmpResponse(const Snmp::Response& response)
{
    debugs(54, 4, HERE);
    Snmp::Inquirer::HandleRemoteAck(response);
}
#endif

int
Ipc::Coordinator::openListenSocket(const SharedListenRequest& request,
                                   int &errNo)
{
    const OpenListenerParams &p = request.params;

    debugs(54, 6, HERE << "opening listen FD at " << p.addr << " for kid" <<
           request.requestorId);

    Ip::Address addr = p.addr; // comm_open_listener may modify it

    enter_suid();
    const int sock = comm_open_listener(p.sock_type, p.proto, addr, p.flags,
                                        FdNote(p.fdNote));
    errNo = (sock >= 0) ? 0 : errno;
    leave_suid();

    // cache positive results
    if (sock >= 0)
        listeners[request.params] = sock;

    return sock;
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
