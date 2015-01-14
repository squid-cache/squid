/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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

