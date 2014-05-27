/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
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
    sbsizesatdestruct = *collectSBufDestructTimeStats();
    mbsizesatdestruct = *collectMemBlobDestructTimeStats();
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

static const bool Registered = (Mgr::RegisterAction("sbuf",
                                "String-Buffer statistics", &SBufStatsAction::Create, 0 , 1),
                                true);
