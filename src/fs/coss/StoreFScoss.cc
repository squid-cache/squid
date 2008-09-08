#error COSS Support is not stable in 3.0. Please do not use.
/*
 * $Id: StoreFScoss.cc,v 1.7 2006/09/03 21:05:21 hno Exp $
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
#include "StoreFScoss.h"
#include "CacheManager.h"
#include "Store.h"
#include "CossSwapDir.h"
#include "store_coss.h"

StoreFScoss StoreFScoss::_instance;

StoreFScoss &
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
    /*  delete coss_index_pool;coss_index_pool = NULL;  XXX Should be here? */
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

void
StoreFScoss::registerWithCacheManager(CacheManager & manager)
{
    manager.registerAction("coss", "COSS Stats", Stats, 0, 1);
}

void
StoreFScoss::Stats(StoreEntry * sentry)
{
    GetInstance().stat(sentry);
}

void
StoreFScoss::stat(StoreEntry *sentry)
{
    stats.stat(sentry);
}

void
CossStats::stat(StoreEntry *sentry)
{
    const char *tbl_fmt = "%10s %10d %10d %10d\n";
    storeAppendPrintf(sentry, "\n                   OPS     SUCCESS        FAIL\n");
    storeAppendPrintf(sentry, tbl_fmt,
                      "open", open.ops, open.success, open.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "create", create.ops, create.success, create.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "close", close.ops, close.success, close.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "unlink", unlink.ops, unlink.success, unlink.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "read", read.ops, read.success, read.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "write", write.ops, write.success, write.fail);
    storeAppendPrintf(sentry, tbl_fmt,
                      "s_write", stripe_write.ops, stripe_write.success, stripe_write.fail);

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "stripes:          %d\n", stripes);
    storeAppendPrintf(sentry, "alloc.alloc:      %d\n", alloc.alloc);
    storeAppendPrintf(sentry, "alloc.realloc:    %d\n", alloc.realloc);
    storeAppendPrintf(sentry, "alloc.collisions: %d\n", alloc.collisions);
    storeAppendPrintf(sentry, "disk_overflows:   %d\n", disk_overflows);
    storeAppendPrintf(sentry, "stripe_overflows: %d\n", stripe_overflows);
    storeAppendPrintf(sentry, "open_mem_hits:    %d\n", open_mem_hits);
    storeAppendPrintf(sentry, "open_mem_misses:  %d\n", open_mem_misses);
}
