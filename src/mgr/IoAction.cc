/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#include "squid.h"
#include "base/TextException.h"
#include "IoStats.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/IoAction.h"
#include "SquidMath.h"
#include "Store.h"
#include "tools.h"

void GetIoStats(Mgr::IoActionData& stats);
void DumpIoStats(Mgr::IoActionData& stats, StoreEntry* sentry);

Mgr::IoActionData::IoActionData()
{
    memset(this, 0, sizeof(*this));
}

Mgr::IoActionData&
Mgr::IoActionData::operator += (const IoActionData& stats)
{
    http_reads += stats.http_reads;
    for (int i = 0; i < IoStats::histSize; ++i)
        http_read_hist[i] += stats.http_read_hist[i];
    ftp_reads += stats.ftp_reads;
    for (int i = 0; i < IoStats::histSize; ++i)
        ftp_read_hist[i] += stats.ftp_read_hist[i];
    gopher_reads += stats.gopher_reads;
    for (int i = 0; i < IoStats::histSize; ++i)
        gopher_read_hist[i] += stats.gopher_read_hist[i];

    return *this;
}

Mgr::IoAction::Pointer
Mgr::IoAction::Create(const CommandPointer &cmd)
{
    return new IoAction(cmd);
}

Mgr::IoAction::IoAction(const CommandPointer &aCmd):
    Action(aCmd), data()
{
    debugs(16, 5, HERE);
}

void
Mgr::IoAction::add(const Action& action)
{
    debugs(16, 5, HERE);
    data += dynamic_cast<const IoAction&>(action).data;
}

void
Mgr::IoAction::collect()
{
    GetIoStats(data);
}

void
Mgr::IoAction::dump(StoreEntry* entry)
{
    debugs(16, 5, HERE);
    Must(entry != NULL);
    DumpIoStats(data, entry);
}

void
Mgr::IoAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(data);
}

void
Mgr::IoAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(data);
}

