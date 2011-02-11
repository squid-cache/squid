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
#include "ipc/UdsOp.h"
#include "mgr/ActionWriter.h"
#include "mgr/Inquirer.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "SquidTime.h"
#include <memory>


CBDATA_NAMESPACED_CLASS_INIT(Mgr, Inquirer);


Mgr::Inquirer::Inquirer(Action::Pointer anAction,
                        const Request &aCause, const Ipc::StrandCoords &coords):
        Ipc::Inquirer(aCause.clone(), coords, anAction->atomic() ? 10 : 100),
        aggrAction(anAction),
        fd(Ipc::ImportFdIntoComm(aCause.fd, SOCK_STREAM, IPPROTO_TCP, Ipc::fdnHttpSocket))
{
    debugs(16, 5, HERE << "FD " << fd << " action: " << aggrAction);

    closer = asyncCall(16, 5, "Mgr::Inquirer::noteCommClosed",
                       CommCbMemFunT<Inquirer, CommCloseCbParams>(this, &Inquirer::noteCommClosed));
    comm_add_close_handler(fd, closer);
}

/// closes our copy of the client HTTP connection socket
void
Mgr::Inquirer::cleanup()
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
    Ipc::Inquirer::start();
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

/// called when the HTTP client or some external force closed our socket
void
Mgr::Inquirer::noteCommClosed(const CommCloseCbParams& params)
{
    debugs(16, 5, HERE);
    Must(fd < 0 || fd == params.fd);
    fd = -1;
    mustStop("commClosed");
}

bool
Mgr::Inquirer::aggregate(Ipc::Response::Pointer aResponse)
{
    Mgr::Response& response = static_cast<Response&>(*aResponse);
    if (response.hasAction())
        aggrAction->add(response.getAction());
    return true;
}

void
Mgr::Inquirer::sendResponse()
{
    if (aggrAction->aggregatable()) {
        removeCloseHandler();
        AsyncJob::Start(new ActionWriter(aggrAction, fd));
        fd = -1; // should not close fd because we passed it to ActionWriter
    }
}

bool
Mgr::Inquirer::doneAll() const
{
    return !writer && Ipc::Inquirer::doneAll();
}
