/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "comm/Write.h"
#include "CommCalls.h"
#include "HttpReply.h"
#include "ipc/Coordinator.h"
#include "mgr/ActionWriter.h"
#include "mgr/Command.h"
#include "mgr/Inquirer.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "SquidTime.h"
#include <memory>
#include <algorithm>


CBDATA_NAMESPACED_CLASS_INIT(Mgr, Inquirer);

Mgr::Inquirer::RequestsMap Mgr::Inquirer::TheRequestsMap;
unsigned int Mgr::Inquirer::LastRequestId = 0;

/// compare Ipc::StrandCoord using kidId, for std::sort() below
static bool
LesserStrandByKidId(const Ipc::StrandCoord &c1, const Ipc::StrandCoord &c2)
{
    return c1.kidId < c2.kidId;
}

Mgr::Inquirer::Inquirer(Action::Pointer anAction, int aFd,
                        const Request &aCause, const Ipc::StrandCoords &coords):
        AsyncJob("Mgr::Inquirer"),
        aggrAction(anAction),
        cause(aCause),
        fd(aFd),
        strands(coords), pos(strands.begin()),
        requestId(0), closer(NULL), timeout(aggrAction->atomic() ? 10 : 100)
{
    debugs(16, 5, HERE << "FD " << aFd << " action: " << aggrAction);

    // order by ascending kid IDs; useful for non-aggregatable stats
    std::sort(strands.begin(), strands.end(), LesserStrandByKidId);

    closer = asyncCall(16, 5, "Mgr::Inquirer::noteCommClosed",
                       CommCbMemFunT<Inquirer, CommCloseCbParams>(this, &Inquirer::noteCommClosed));
    comm_add_close_handler(fd, closer);
}

Mgr::Inquirer::~Inquirer()
{
    debugs(16, 5, HERE);
    close();
}

/// closes our copy of the client HTTP connection socket
void
Mgr::Inquirer::close()
{
    if (fd >= 0) {
        removeCloseHandler();
        comm_close(fd);
        fd = -1;
    }
}

void
Mgr::Inquirer::removeCloseHandler()
{
    if (closer != NULL) {
        comm_remove_close_handler(fd, closer);
        closer = NULL;
    }
}

void
Mgr::Inquirer::start()
{
    debugs(16, 5, HERE);
    Must(fd >= 0);
    Must(aggrAction != NULL);

    std::auto_ptr<HttpReply> reply(new HttpReply);
    reply->setHeaders(HTTP_OK, NULL, "text/plain", -1, squid_curtime, squid_curtime);
    reply->header.putStr(HDR_CONNECTION, "close"); // until we chunk response
    std::auto_ptr<MemBuf> replyBuf(reply->pack());
    writer = asyncCall(16, 5, "Mgr::Inquirer::noteWroteHeader",
                       CommCbMemFunT<Inquirer, CommIoCbParams>(this, &Inquirer::noteWroteHeader));
    Comm::Write(fd, replyBuf.get(), writer);
}

/// called when we wrote the response header
void
Mgr::Inquirer::noteWroteHeader(const CommIoCbParams& params)
{
    debugs(16, 5, HERE);
    writer = NULL;
    Must(params.flag == COMM_OK);
    Must(params.fd == fd);
    Must(params.size != 0);
    // start inquiries at the initial pos
    inquire();
}

void
Mgr::Inquirer::inquire()
{
    if (pos == strands.end()) {
        Must(done());
        return;
    }

    Must(requestId == 0);
    AsyncCall::Pointer callback = asyncCall(16, 5, "Mgr::Inquirer::handleRemoteAck",
                                            HandleAckDialer(this, &Inquirer::handleRemoteAck, Response()));
    if (++LastRequestId == 0) // don't use zero value as requestId
        ++LastRequestId;
    requestId = LastRequestId;
    const int kidId = pos->kidId;
    debugs(16, 4, HERE << "inquire kid: " << kidId << status());
    TheRequestsMap[requestId] = callback;
    Request mgrRequest(KidIdentifier, requestId, fd,
                       aggrAction->command().params);
    Ipc::TypedMsgHdr message;
    mgrRequest.pack(message);
    Ipc::SendMessage(Ipc::Port::MakeAddr(Ipc::strandAddrPfx, kidId), message);
    eventAdd("Mgr::Inquirer::requestTimedOut", &Inquirer::RequestTimedOut,
             this, timeout, 0, false);
}

/// called when a strand is done writing its output
void
Mgr::Inquirer::handleRemoteAck(const Response& response)
{
    debugs(16, 4, HERE << status());
    requestId = 0;
    removeTimeoutEvent();
    if (response.hasAction())
        aggrAction->add(response.getAction());
    Must(!done()); // or we should not be called
    ++pos; // advance after a successful inquiry
    inquire();
}

/// called when the HTTP client or some external force closed our socket
void
Mgr::Inquirer::noteCommClosed(const CommCloseCbParams& params)
{
    debugs(16, 5, HERE);
    Must(fd < 0 || fd == params.fd);
    fd = -1;
    mustStop("commClosed");
}

void
Mgr::Inquirer::swanSong()
{
    debugs(16, 5, HERE);
    removeTimeoutEvent();
    if (requestId > 0) {
        DequeueRequest(requestId);
        requestId = 0;
    }
    if (aggrAction->aggregatable()) {
        removeCloseHandler();
        AsyncJob::Start(new ActionWriter(aggrAction, fd));
        fd = -1; // should not close fd because we passed it to ActionWriter
    }
    close();
}

bool
Mgr::Inquirer::doneAll() const
{
    return !writer && pos == strands.end();
}

/// returns and forgets the right Inquirer callback for strand request
AsyncCall::Pointer
Mgr::Inquirer::DequeueRequest(unsigned int requestId)
{
    debugs(16, 3, HERE << " requestId " << requestId);
    Must(requestId != 0);
    AsyncCall::Pointer call;
    RequestsMap::iterator request = TheRequestsMap.find(requestId);
    if (request != TheRequestsMap.end()) {
        call = request->second;
        Must(call != NULL);
        TheRequestsMap.erase(request);
    }
    return call;
}

void
Mgr::Inquirer::HandleRemoteAck(const Mgr::Response& response)
{
    Must(response.requestId != 0);
    AsyncCall::Pointer call = DequeueRequest(response.requestId);
    if (call != NULL) {
        HandleAckDialer* dialer = dynamic_cast<HandleAckDialer*>(call->getDialer());
        Must(dialer);
        dialer->arg1 = response;
        ScheduleCallHere(call);
    }
}

/// called when we are no longer waiting for the strand to respond
void
Mgr::Inquirer::removeTimeoutEvent()
{
    if (eventFind(&Inquirer::RequestTimedOut, this))
        eventDelete(&Inquirer::RequestTimedOut, this);
}

/// Mgr::Inquirer::requestTimedOut wrapper
void
Mgr::Inquirer::RequestTimedOut(void* param)
{
    debugs(16, 3, HERE);
    Must(param != NULL);
    Inquirer* cmi = static_cast<Inquirer*>(param);
    // use async call to enable job call protection that time events lack
    CallJobHere(16, 5, cmi, Mgr::Inquirer, requestTimedOut);
}

/// called when the strand failed to respond (or finish responding) in time
void
Mgr::Inquirer::requestTimedOut()
{
    debugs(16, 3, HERE);
    if (requestId != 0) {
        DequeueRequest(requestId);
        requestId = 0;
        Must(!done()); // or we should not be called
        ++pos; // advance after a failed inquiry
        inquire();
    }
}

const char*
Mgr::Inquirer::status() const
{
    static MemBuf buf;
    buf.reset();
    buf.Printf(" [FD %d, requestId %u]", fd, requestId);
    buf.terminate();
    return buf.content();
}
