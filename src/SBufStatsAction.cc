/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ipc/Messages.h"
#include "ipc/TypedMsgHdr.h"
#include "mgr/Registration.h"
#include "SBufDetailedStats.h"
#include "SBufStatsAction.h"
#include "StoreEntryStream.h"

SBufStatsAction::SBufStatsAction(const Mgr::CommandPointer &cmd_):
    Action(cmd_)
{ } //default constructor is OK for data member

SBufStatsAction::Pointer
SBufStatsAction::Create(const Mgr::CommandPointer &cmd)
{
    return new SBufStatsAction(cmd);
}

void
SBufStatsAction::add(const Mgr::Action& action)
{
    sbdata += dynamic_cast<const SBufStatsAction&>(action).sbdata;
    mbdata += dynamic_cast<const SBufStatsAction&>(action).mbdata;
    sbsizesatdestruct += dynamic_cast<const SBufStatsAction&>(action).sbsizesatdestruct;
    mbsizesatdestruct += dynamic_cast<const SBufStatsAction&>(action).mbsizesatdestruct;
}

void
SBufStatsAction::collect()
{
    sbdata = SBuf::GetStats();
    mbdata = MemBlob::GetStats();
    sbsizesatdestruct = collectSBufDestructTimeStats();
    mbsizesatdestruct = collectMemBlobDestructTimeStats();
}

static void
statHistSBufDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count == 0)
        return;
    storeAppendPrintf(sentry, "\t%d-%d\t%d\n", static_cast<int>(val), static_cast<int>(val+size), count);
}

void
SBufStatsAction::dump(StoreEntry* entry)
{
    StoreEntryStream ses(entry);
    ses << "\n\n\nThese statistics are experimental; their format and contents "
        "should not be relied upon, they are bound to change as "
        "the SBuf feature is evolved\n";
    sbdata.dump(ses);
    mbdata.dump(ses);
    ses << "\n";
    ses << "SBuf size distribution at destruct time:\n";
    sbsizesatdestruct.dump(entry,statHistSBufDumper);
    ses << "MemBlob capacity distribution at destruct time:\n";
    mbsizesatdestruct.dump(entry,statHistSBufDumper);
}

void
SBufStatsAction::pack(Ipc::TypedMsgHdr& msg) const
{
    msg.setType(Ipc::mtCacheMgrResponse);
    msg.putPod(sbdata);
    msg.putPod(mbdata);
}

void
SBufStatsAction::unpack(const Ipc::TypedMsgHdr& msg)
{
    msg.checkType(Ipc::mtCacheMgrResponse);
    msg.getPod(sbdata);
    msg.getPod(mbdata);
}

void
SBufStatsAction::RegisterWithCacheManager()
{
    Mgr::RegisterAction("sbuf", "String-Buffer statistics", &SBufStatsAction::Create, 0 , 1);
}

