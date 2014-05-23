
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "DiskDaemonDiskIOModule.h"
#include "DiskdIOStrategy.h"
#include "DiskIO/DiskDaemon/DiskdAction.h"
#include "mgr/Registration.h"
#include "Store.h"

DiskDaemonDiskIOModule::DiskDaemonDiskIOModule() : initialised(false)
{
    ModuleAdd(*this);
}

DiskDaemonDiskIOModule &
DiskDaemonDiskIOModule::GetInstance()
{
    return Instance;
}

void
DiskDaemonDiskIOModule::init()
{
    /* We may be reused - for instance in coss - eventually.
     * When we do, we either need per-using-module stats (
     * no singleton pattern), or we need to refcount the
     * initialisation level and handle multiple clients.
     * RBC - 20030718.
     */
    assert(!initialised);
    memset(&diskd_stats, '\0', sizeof(diskd_stats));
#if 0
    /*
     * DPW 2007-04-12
     * No debugging here please because this method is called before
     * the debug log is configured and we'll get the message on
     * stderr when doing things like 'squid -k reconfigure'
     */
    debugs(47, DBG_IMPORTANT, "diskd started");
#endif
    initialised = true;

    registerWithCacheManager();
}

void
DiskDaemonDiskIOModule::registerWithCacheManager(void)
{
    Mgr::RegisterAction("diskd", "DISKD Stats", &DiskdAction::Create, 0, 1);
}

void
DiskDaemonDiskIOModule::gracefulShutdown()
{
    initialised = false;
}

DiskIOStrategy *
DiskDaemonDiskIOModule::createStrategy()
{
    return new DiskdIOStrategy();
}

DiskDaemonDiskIOModule DiskDaemonDiskIOModule::Instance;

char const *
DiskDaemonDiskIOModule::type () const
{
    return "DiskDaemon";
}
