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
#include "HttpRequest.h"
#include "ipc/UdsOp.h"
#include "mgr/ActionWriter.h"
#include "mgr/IntParam.h"
#include "mgr/Inquirer.h"
#include "mgr/Command.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "SquidTime.h"
#include "errorpage.h"
#include <memory>
#include <algorithm>


CBDATA_NAMESPACED_CLASS_INIT(Mgr, Inquirer);


Mgr::Inquirer::Inquirer(Action::Pointer anAction,
                        const Request &aCause, const Ipc::StrandCoords &coords):
        Ipc::Inquirer(aCause.clone(), applyQueryParams(coords, aCause.params.queryParams), anAction->atomic() ? 10 : 100),
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

    std::auto_ptr<MemBuf> replyBuf;
    if (strands.empty()) {
        LOCAL_ARRAY(char, url, MAX_URL);
        snprintf(url, MAX_URL, "%s", aggrAction->command().params.httpUri.termedBuf());
        HttpRequest *req = HttpRequest::CreateFromUrl(url);
        ErrorState *err = errorCon(ERR_INVALID_URL, HTTP_NOT_FOUND, req);
        std::auto_ptr<HttpReply> reply(err->BuildHttpReply());
        replyBuf.reset(reply->pack());
        errorStateFree(err);
    } else {
        std::auto_ptr<HttpReply> reply(new HttpReply);
        reply->setHeaders(HTTP_OK, NULL, "text/plain", -1, squid_curtime, squid_curtime);
        reply->header.putStr(HDR_CONNECTION, "close"); // until we chunk response
        replyBuf.reset(reply->pack());
    }
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
    if (!strands.empty() && aggrAction->aggregatable()) {
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

Ipc::StrandCoords
Mgr::Inquirer::applyQueryParams(const Ipc::StrandCoords& aStrands, const QueryParams& aParams)
{
    Ipc::StrandCoords sc;

    QueryParam::Pointer processesParam = aParams.get("processes");
    QueryParam::Pointer workersParam = aParams.get("workers");

    if (processesParam == NULL || workersParam == NULL) {
        if (processesParam != NULL) {
            IntParam* param = dynamic_cast<IntParam*>(processesParam.getRaw());
            if (param != NULL && param->type == QueryParam::ptInt) {
                const std::vector<int>& processes = param->value();
                for (Ipc::StrandCoords::const_iterator iter = aStrands.begin();
                        iter != aStrands.end(); ++iter) {
                    if (std::find(processes.begin(), processes.end(), iter->kidId) != processes.end())
                        sc.push_back(*iter);
                }
            }
        } else if (workersParam != NULL) {
            IntParam* param = dynamic_cast<IntParam*>(workersParam.getRaw());
            if (param != NULL && param->type == QueryParam::ptInt) {
                const std::vector<int>& workers = param->value();
                for (int i = 0; i < (int)aStrands.size(); ++i) {
                    if (std::find(workers.begin(), workers.end(), i + 1) != workers.end())
                        sc.push_back(aStrands[i]);
                }
            }
        } else {
            sc = aStrands;
        }
    }

    debugs(0, 0, HERE << "strands kid IDs = ");
    for (Ipc::StrandCoords::const_iterator iter = sc.begin(); iter != sc.end(); ++iter) {
        debugs(0, 0, HERE << iter->kidId);
    }

    return sc;
}
