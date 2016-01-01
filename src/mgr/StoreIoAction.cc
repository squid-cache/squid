/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/StoreIoAction.h"
#include "Store.h"
#include "tools.h"

Mgr::StoreIoActionData::StoreIoActionData()
{
    memset(this, 0, sizeof(*this));
}

Mgr::StoreIoActionData&
Mgr::StoreIoActionData::operator += (const StoreIoActionData& stats)
{
    create_calls += stats.create_calls;
    create_select_fail += stats.create_select_fail;
    create_create_fail += stats.create_create_fail;
    create_success += stats.create_success;

    return *this;
}

Mgr::StoreIoAction::Pointer
Mgr::StoreIoAction::Create(const CommandPointer &cmd)
{
    return new StoreIoAction(cmd);
}

Mgr::StoreIoAction::StoreIoAction(const CommandPointer &aCmd):
    Action(aCmd), data()
{
    debugs(16, 5, HERE);
}

void
Mgr::StoreIoAction::add(const Action& action)
{
    debugs(16, 5, HERE);
    data += dynamic_cast<const StoreIoAction&>(action).data;
}

void
Mgr::StoreIoAction::collect()
{
    data.create_calls = store_io_stats.create.calls;
    data.create_select_fail = store_io_stats.create.select_fail;
    data.create_create_fail = store_io_stats.create.create_fail;
    data.create_success = store_io_stats.create.success;
}

void
Mgr::StoreIoAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    storeAppendPrintf(entry, "Store IO Interface Stats\n");
    storeAppendPrintf(entry, "create.calls %.0f\n", data.create_calls);
    storeAppendPrintf(entry, "create.select_fail %.0f\n", data.create_select_fail);
    storeAppendPrintf(entry, "create.create_fail %.0f\n", data.create_create_fail);
    storeAppendPrintf(entry, "create.success %.0f\n", data.create_success);
}

void
Mgr::StoreIoAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(data);
}

void
Mgr::StoreIoAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(data);
}

