/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "ipc/UdsOp.h"
#include "mgr/Command.h"
#include "mgr/Filler.h"
#include "mgr/FunAction.h"
#include "mgr/Request.h"
#include "Store.h"


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
    const int fd = Ipc::ImportFdIntoComm(request.fd, SOCK_STREAM, IPPROTO_TCP, Ipc::fdnHttpSocket);
    Must(fd >= 0);
    Must(request.requestId != 0);
    AsyncJob::Start(new Mgr::Filler(this, fd, request.requestId));
}

void
Mgr::FunAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    if (UsingSmp() && IamWorkerProcess())
        storeAppendPrintf(entry, "by kid%d {\n", KidIdentifier);
    handler(entry);
    if (atomic() && UsingSmp() && IamWorkerProcess())
        storeAppendPrintf(entry, "} by kid%d\n\n", KidIdentifier);
}
