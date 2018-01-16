/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "globals.h"
#include "ipc/UdsOp.h"
#include "mgr/Command.h"
#include "mgr/Filler.h"
#include "mgr/FunAction.h"
#include "mgr/Request.h"
#include "Store.h"
#include "tools.h"

Mgr::FunAction::Pointer
Mgr::FunAction::Create(const Command::Pointer &aCmd, OBJH* aHandler)
{
    return new FunAction(aCmd, aHandler);
}

Mgr::FunAction::FunAction(const Command::Pointer &aCmd, OBJH* aHandler):
    Action(aCmd), handler(aHandler)
{
    Must(handler != NULL);
    debugs(16, 5, HERE);
}

void
Mgr::FunAction::respond(const Request& request)
{
    debugs(16, 5, HERE);
    Ipc::ImportFdIntoComm(request.conn, SOCK_STREAM, IPPROTO_TCP, Ipc::fdnHttpSocket);
    Must(Comm::IsConnOpen(request.conn));
    Must(request.requestId != 0);
    AsyncJob::Start(new Mgr::Filler(this, request.conn, request.requestId));
}

void
Mgr::FunAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    if (UsingSmp())
        storeAppendPrintf(entry, "by kid%d {\n", KidIdentifier);
    handler(entry);
    if (atomic() && UsingSmp())
        storeAppendPrintf(entry, "} by kid%d\n\n", KidIdentifier);
}

