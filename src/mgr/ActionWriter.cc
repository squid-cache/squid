/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "mgr/ActionWriter.h"
#include "Store.h"

CBDATA_NAMESPACED_CLASS_INIT(Mgr, ActionWriter);

Mgr::ActionWriter::ActionWriter(const Action::Pointer &anAction, const Comm::ConnectionPointer &conn):
    StoreToCommWriter(conn, anAction->createStoreEntry()),
    action(anAction)
{
    debugs(16, 5, conn << " action: " << action);
}

void
Mgr::ActionWriter::start()
{
    debugs(16, 5, MYNAME);
    Must(action != nullptr);

    StoreToCommWriter::start();
    action->fillEntry(entry, false);
}

