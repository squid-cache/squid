/*
 * $Id$
 *
 * DEBUG: section 16    Cache Manager API
 *
 */

#include "config.h"
#include "base/TextException.h"
#include "mgr/ActionWriter.h"
#include "Store.h"


CBDATA_NAMESPACED_CLASS_INIT(Mgr, ActionWriter);

Mgr::ActionWriter::ActionWriter(const Action::Pointer &anAction, int aFd):
        StoreToCommWriter(aFd, anAction->createStoreEntry()),
        action(anAction)
{
    debugs(16, 5, HERE << "FD " << aFd << " action: " << action);
}

void
Mgr::ActionWriter::start()
{
    debugs(16, 5, HERE);
    Must(action != NULL);

    StoreToCommWriter::start();
    action->fillEntry(entry, false);
}
