
/*
 * $Id: StoreFScoss.cc,v 1.2 2003/08/27 21:19:38 wessels Exp $
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Robert Collins
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

#include "StoreFileSystem.h"
#include "fs/coss/StoreFScoss.h"
#include "store_coss.h"
#include "Store.h"

struct _coss_stats coss_stats;

static void storeCossStats(StoreEntry *);

StoreFScoss StoreFScoss::_instance;

StoreFileSystem &
StoreFScoss::GetInstance()
{
    return _instance;
}

StoreFScoss::StoreFScoss()
{
    FsAdd(*this);
}

char const *
StoreFScoss::type() const
{
    return "coss";
}

void
StoreFScoss::done()
{
    /*  memPoolDestroy(&coss_index_pool);  XXX Should be here? */
    cachemgrRegister("coss", "COSS Stats", storeCossStats, 0, 1);
    initialised = false;
}

SwapDir *
StoreFScoss::createSwapDir()
{
    SwapDir *result = new CossSwapDir;
    return result;
}


void
StoreFScoss::setup()
{
    assert(!initialised);

    coss_index_pool = memPoolCreate("COSS index data", sizeof(CossIndexNode));
    initialised = true;
}

static void
storeCossStats(StoreEntry * sentry)
{
    const char *tbl_fmt = "%10s %10d %10d %10d\n";
    storeAppendPrintf(sentry, "\n                   OPS     SUCCESS        FAIL\n");
    storeAppendPrintf(sentry, tbl_fmt,
                      "open", coss_stats.open.ops, coss_stats.open.success, coss_stats.open.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "create", coss_stats.create.ops, coss_stats.create.success, coss_stats.create.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "close", coss_stats.close.ops, coss_stats.close.success, coss_stats.close.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "unlink", coss_stats.unlink.ops, coss_stats.unlink.success, coss_stats.unlink.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "read", coss_stats.read.ops, coss_stats.read.success, coss_stats.read.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "write", coss_stats.write.ops, coss_stats.write.success, coss_stats.write.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "s_write", coss_stats.stripe_write.ops, coss_stats.stripe_write.success, coss_stats.stripe_write.fail);

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "stripes:          %d\n", coss_stats.stripes);
    storeAppendPrintf(sentry, "alloc.alloc:      %d\n", coss_stats.alloc.alloc);
    storeAppendPrintf(sentry, "alloc.realloc:    %d\n", coss_stats.alloc.realloc);
    storeAppendPrintf(sentry, "alloc.collisions: %d\n", coss_stats.alloc.collisions);
    storeAppendPrintf(sentry, "disk_overflows:   %d\n", coss_stats.disk_overflows);
    storeAppendPrintf(sentry, "stripe_overflows: %d\n", coss_stats.stripe_overflows);
    storeAppendPrintf(sentry, "open_mem_hits:    %d\n", coss_stats.open_mem_hits);
    storeAppendPrintf(sentry, "open_mem_misses:  %d\n", coss_stats.open_mem_misses);
}
