
/*
 * $Id: DiskDaemonDiskIOModule.cc,v 1.3 2006/05/29 00:15:03 robertc Exp $
 *
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
#include "CacheManager.h"
#include "DiskdIOStrategy.h"
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
    debugs(47, 1, "diskd started");
    initialised = true;
}

void
DiskDaemonDiskIOModule::registerWithCacheManager(CacheManager & manager)
{
    manager.registerAction("diskd", "DISKD Stats", Stats, 0, 1);
}

void
DiskDaemonDiskIOModule::shutdown()
{
    initialised = false;
}

DiskIOStrategy *
DiskDaemonDiskIOModule::createStrategy()
{
    return new DiskdIOStrategy();
}

DiskDaemonDiskIOModule DiskDaemonDiskIOModule::Instance;

void
DiskDaemonDiskIOModule::Stats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "sent_count: %d\n", diskd_stats.sent_count);
    storeAppendPrintf(sentry, "recv_count: %d\n", diskd_stats.recv_count);
    storeAppendPrintf(sentry, "max_away: %d\n", diskd_stats.max_away);
    storeAppendPrintf(sentry, "max_shmuse: %d\n", diskd_stats.max_shmuse);
    storeAppendPrintf(sentry, "open_fail_queue_len: %d\n", diskd_stats.open_fail_queue_len);
    storeAppendPrintf(sentry, "block_queue_len: %d\n", diskd_stats.block_queue_len);
    diskd_stats.max_away = diskd_stats.max_shmuse = 0;
    storeAppendPrintf(sentry, "\n              OPS   SUCCESS    FAIL\n");
    storeAppendPrintf(sentry, "%7s %9d %9d %7d\n",
                      "open", diskd_stats.open.ops, diskd_stats.open.success, diskd_stats.open.fail);
    storeAppendPrintf(sentry, "%7s %9d %9d %7d\n",
                      "create", diskd_stats.create.ops, diskd_stats.create.success, diskd_stats.create.fail);
    storeAppendPrintf(sentry, "%7s %9d %9d %7d\n",
                      "close", diskd_stats.close.ops, diskd_stats.close.success, diskd_stats.close.fail);
    storeAppendPrintf(sentry, "%7s %9d %9d %7d\n",
                      "unlink", diskd_stats.unlink.ops, diskd_stats.unlink.success, diskd_stats.unlink.fail);
    storeAppendPrintf(sentry, "%7s %9d %9d %7d\n",
                      "read", diskd_stats.read.ops, diskd_stats.read.success, diskd_stats.read.fail);
    storeAppendPrintf(sentry, "%7s %9d %9d %7d\n",
                      "write", diskd_stats.write.ops, diskd_stats.write.success, diskd_stats.write.fail);
}

char const *
DiskDaemonDiskIOModule::type () const
{
    return "DiskDaemon";
}
