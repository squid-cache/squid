/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "mgr/Filler.h"
#include "mgr/Response.h"
#include "Store.h"


CBDATA_NAMESPACED_CLASS_INIT(Mgr, Filler);

Mgr::Filler::Filler(const Action::Pointer &anAction, int aFd,
                    unsigned int aRequestId):
        StoreToCommWriter(aFd, anAction->createStoreEntry()),
        action(anAction),
        requestId(aRequestId)
{
    debugs(16, 5, HERE << "FD " << aFd << " action: " << action);
}

void
Mgr::Filler::start()
{
    debugs(16, 5, HERE);
    Must(requestId != 0);
    Must(action != NULL);

    StoreToCommWriter::start();
    action->run(entry, false);
}

void
Mgr::Filler::swanSong()
{
    debugs(16, 5, HERE);
    action->sendResponse(requestId);
    StoreToCommWriter::swanSong();
}
