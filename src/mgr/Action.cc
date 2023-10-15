/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "CacheManager.h"
#include "comm/Connection.h"
#include "HttpReply.h"
#include "ipc/Port.h"
#include "mgr/Action.h"
#include "mgr/ActionCreator.h"
#include "mgr/ActionParams.h"
#include "mgr/ActionProfile.h"
#include "mgr/Command.h"
#include "mgr/Request.h"
#include "mgr/Response.h"
#include "Store.h"

Mgr::Action::Action(const Command::Pointer &aCmd): cmd(aCmd)
{
    Must(cmd != nullptr);
    Must(cmd->profile != nullptr);
}

Mgr::Action::~Action()
{
}

const Mgr::Command &
Mgr::Action::command() const
{
    Must(cmd != nullptr);
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
Mgr::Action::add(const Action &)
{
}

void
Mgr::Action::respond(const Request &request)
{
    debugs(16, 5, MYNAME);

    // Assume most kid classes are fully aggregatable (i.e., they do not dump
    // local info at all). Do not import the remote HTTP fd into our Comm
    // space; collect and send an IPC msg with collected info to Coordinator.
    ::close(request.conn->fd);
    request.conn->fd = -1;
    collect();
    sendResponse(request.requestId);
}

void
Mgr::Action::sendResponse(const Ipc::RequestId requestId)
{
    Response response(requestId, this);
    Ipc::TypedMsgHdr message;
    response.pack(message);
    Ipc::SendMessage(Ipc::Port::CoordinatorAddr(), message);
}

void
Mgr::Action::run(StoreEntry* entry, bool writeHttpHeader)
{
    debugs(16, 5, MYNAME);
    collect();
    fillEntry(entry, writeHttpHeader);
}

void
Mgr::Action::fillEntry(StoreEntry* entry, bool writeHttpHeader)
{
    debugs(16, 5, MYNAME);
    entry->buffer();

    if (writeHttpHeader) {
        HttpReply *rep = new HttpReply;
        rep->setHeaders(Http::scOkay, nullptr, contentType(), -1, squid_curtime, squid_curtime);

        const auto &origin = command().params.httpOrigin;
        const auto originOrNil = origin.size() ? origin.termedBuf() : nullptr;
        CacheManager::PutCommonResponseHeaders(*rep, originOrNil);

        entry->replaceHttpReply(rep);
    }

    dump(entry);

    entry->flush();

    if (atomic())
        entry->complete();
}

