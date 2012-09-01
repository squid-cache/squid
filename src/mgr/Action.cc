/*
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "squid.h"
#include "comm/Connection.h"
#include "HttpReply.h"
#include "ipc/Port.h"
#include "mgr/ActionCreator.h"
#include "mgr/Action.h"
#include "mgr/ActionParams.h"
#include "mgr/ActionProfile.h"
#include "mgr/Command.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "SquidTime.h"
#include "Store.h"

Mgr::Action::Action(const Command::Pointer &aCmd): cmd(aCmd)
{
    Must(cmd != NULL);
    Must(cmd->profile != NULL);
}

Mgr::Action::~Action()
{
}

const Mgr::Command &
Mgr::Action::command() const
{
    Must(cmd != NULL);
    return *cmd;
}

bool
Mgr::Action::atomic() const
{
    return command().profile->isAtomic;
}

const char*
Mgr::Action::name() const
{
    return command().profile->name;
}

StoreEntry*
Mgr::Action::createStoreEntry() const
{
    const ActionParams &params = command().params;
    const char *uri = params.httpUri.termedBuf();
    return storeCreateEntry(uri, uri, params.httpFlags, params.httpMethod);
}

void
Mgr::Action::add(const Action& action)
{
}

void
Mgr::Action::respond(const Request& request)
{
    debugs(16, 5, HERE);

    // Assume most kid classes are fully aggregatable (i.e., they do not dump
    // local info at all). Do not import the remote HTTP fd into our Comm
    // space; collect and send an IPC msg with collected info to Coordinator.
    ::close(request.conn->fd);
    request.conn->fd = -1;
    collect();
    sendResponse(request.requestId);
}

void
Mgr::Action::sendResponse(unsigned int requestId)
{
    Response response(requestId, this);
    Ipc::TypedMsgHdr message;
    response.pack(message);
    Ipc::SendMessage(Ipc::coordinatorAddr, message);
}

void
Mgr::Action::run(StoreEntry* entry, bool writeHttpHeader)
{
    debugs(16, 5, HERE);
    collect();
    fillEntry(entry, writeHttpHeader);
}

void
Mgr::Action::fillEntry(StoreEntry* entry, bool writeHttpHeader)
{
    debugs(16, 5, HERE);
    entry->buffer();

    if (writeHttpHeader) {
        HttpReply *rep = new HttpReply;
        rep->setHeaders(HTTP_OK, NULL, "text/plain", -1, squid_curtime, squid_curtime);
        // Allow cachemgr and other XHR scripts access to our version string
        const ActionParams &params = command().params;
        if (params.httpOrigin.size() > 0) {
            rep->header.putExt("Access-Control-Allow-Origin", params.httpOrigin.termedBuf());
#if HAVE_AUTH_MODULE_BASIC
            rep->header.putExt("Access-Control-Allow-Credentials","true");
#endif
            rep->header.putExt("Access-Control-Expose-Headers","Server");
        }
        entry->replaceHttpReply(rep);
    }

    dump(entry);

    entry->flush();

    if (atomic())
        entry->complete();
}
