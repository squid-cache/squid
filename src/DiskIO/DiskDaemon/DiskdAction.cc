/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Squid-side DISKD I/O functions. */

#include "squid.h"
#include "base/TextException.h"
#include "DiskIO/DiskDaemon/DiskdAction.h"
#include "DiskIO/DiskDaemon/DiskdIOStrategy.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/ActionWriter.h"
#include "Store.h"
#include "tools.h"

DiskdActionData::DiskdActionData()
{
    memset(this, 0, sizeof(*this));
}

DiskdActionData&
DiskdActionData::operator += (const DiskdActionData& stats)
{
    sent_count += stats.sent_count;
    recv_count += stats.recv_count;
    if (stats.max_away > max_away)
        max_away = stats.max_away;
    if (stats.max_shmuse > max_shmuse)
        max_shmuse += stats.max_shmuse;
    open_fail_queue_len += stats.open_fail_queue_len;
    block_queue_len += stats.block_queue_len;
    open_ops += stats.open_ops;
    open_success += stats.open_success;
    open_fail += stats.open_fail;
    create_ops += stats.create_ops;
    create_success += stats.create_success;
    create_fail += stats.create_fail;
    close_ops += stats.close_ops;
    close_success += stats.close_success;
    close_fail += stats.close_fail;
    unlink_ops += stats.unlink_ops;
    unlink_success += stats.unlink_success;
    unlink_fail += stats.unlink_fail;
    read_ops += stats.read_ops;
    read_success += stats.read_success;
    read_fail += stats.read_fail;
    write_ops += stats.write_ops;
    write_success += stats.write_success;
    write_fail += stats.write_fail;

    return *this;
}

DiskdAction::Pointer
DiskdAction::Create(const Mgr::CommandPointer &aCmd)
{
    return new DiskdAction(aCmd);
}

DiskdAction::DiskdAction(const Mgr::CommandPointer &aCmd):
    Action(aCmd), data()
{
    debugs(79, 5, HERE);
}

void
DiskdAction::add(const Action& action)
{
    debugs(79, 5, HERE);
    data += dynamic_cast<const DiskdAction&>(action).data;
}

void
DiskdAction::collect()
{
    data.sent_count = diskd_stats.sent_count;
    data.recv_count = diskd_stats.recv_count;
    data.max_away = diskd_stats.max_away;
    data.max_shmuse = diskd_stats.max_shmuse;
    data.open_fail_queue_len = diskd_stats.open_fail_queue_len;
    data.block_queue_len = diskd_stats.block_queue_len;
    diskd_stats.max_away = diskd_stats.max_shmuse = 0;

    data.open_ops = diskd_stats.open.ops;
    data.open_success = diskd_stats.open.success;
    data.open_fail = diskd_stats.open.fail;

    data.create_ops = diskd_stats.create.ops;
    data.create_success = diskd_stats.create.success;
    data.create_fail = diskd_stats.create.fail;

    data.close_ops = diskd_stats.close.ops;
    data.close_success = diskd_stats.close.success;
    data.close_fail = diskd_stats.close.fail;

    data.unlink_ops = diskd_stats.unlink.ops;
    data.unlink_success = diskd_stats.unlink.success;
    data.unlink_fail = diskd_stats.unlink.fail;

    data.read_ops = diskd_stats.read.ops;
    data.read_success = diskd_stats.read.success;
    data.read_fail = diskd_stats.read.fail;

    data.write_ops = diskd_stats.write.ops;
    data.write_success = diskd_stats.write.success;
    data.write_fail = diskd_stats.write.fail;
}

void
DiskdAction::dump(StoreEntry* entry)
{
    debugs(79, 5, HERE);
    Must(entry != NULL);
    storeAppendPrintf(entry, "sent_count: %.0f\n", data.sent_count);
    storeAppendPrintf(entry, "recv_count: %.0f\n", data.recv_count);
    storeAppendPrintf(entry, "max_away: %.0f\n", data.max_away);
    storeAppendPrintf(entry, "max_shmuse: %.0f\n", data.max_shmuse);
    storeAppendPrintf(entry, "open_fail_queue_len: %.0f\n", data.open_fail_queue_len);
    storeAppendPrintf(entry, "block_queue_len: %.0f\n", data.block_queue_len);
    storeAppendPrintf(entry, "\n              OPS   SUCCESS    FAIL\n");
    storeAppendPrintf(entry, "%7s %9.0f %9.0f %7.0f\n",
                      "open", data.open_ops, data.open_success, data.open_fail);
    storeAppendPrintf(entry, "%7s %9.0f %9.0f %7.0f\n",
                      "create", data.create_ops, data.create_success, data.create_fail);
    storeAppendPrintf(entry, "%7s %9.0f %9.0f %7.0f\n",
                      "close", data.close_ops, data.close_success, data.close_fail);
    storeAppendPrintf(entry, "%7s %9.0f %9.0f %7.0f\n",
                      "unlink", data.unlink_ops, data.unlink_success, data.unlink_fail);
    storeAppendPrintf(entry, "%7s %9.0f %9.0f %7.0f\n",
                      "read", data.read_ops, data.read_success, data.read_fail);
    storeAppendPrintf(entry, "%7s %9.0f %9.0f %7.0f\n",
                      "write", data.write_ops, data.write_success, data.write_fail);
}

void
DiskdAction::pack(Ipc::TypedMsgHdr& hdrMsg) const
{
    hdrMsg.setType(Ipc::mtCacheMgrResponse);
    hdrMsg.putPod(data);
}

void
DiskdAction::unpack(const Ipc::TypedMsgHdr& hdrMsg)
{
    hdrMsg.checkType(Ipc::mtCacheMgrResponse);
    hdrMsg.getPod(data);
}

