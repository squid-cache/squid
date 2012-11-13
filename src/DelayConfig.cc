
/*
 * DEBUG: section 77    Delay Pools
 * AUTHOR: Robert Collins <robertc@squid-cache.org>
 * Based upon original delay pools code by
 *   David Luyer <david@luyer.net>
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "ConfigParser.h"
#include "DelayConfig.h"
#include "DelayPool.h"
#include "DelayPools.h"
#include "Store.h"

void
DelayConfig::parsePoolCount()
{
    unsigned short pools_;
    ConfigParser::ParseUShort(&pools_);
    DelayPools::pools(pools_);
}

void
DelayConfig::parsePoolClass()
{
    unsigned short pool;

    ConfigParser::ParseUShort(&pool);

    if (pool < 1 || pool > DelayPools::pools()) {
        debugs(3, DBG_CRITICAL, "parse_delay_pool_class: Ignoring pool " << pool << " not in 1 .. " << DelayPools::pools());
        return;
    }

    unsigned short delay_class_;
    ConfigParser::ParseUShort(&delay_class_);

    if (delay_class_ < 1 || delay_class_ > 5) {
        debugs(3, DBG_CRITICAL, "parse_delay_pool_class: Ignoring pool " << pool << " class " << delay_class_ << " not in 1 .. 5");
        return;
    }

    --pool;

    DelayPools::delay_data[pool].createPool(delay_class_);
}

void
DelayConfig::parsePoolRates()
{
    unsigned short pool;
    ConfigParser::ParseUShort(&pool);

    if (pool < 1 || pool > DelayPools::pools()) {
        debugs(3, DBG_CRITICAL, "parse_delay_pool_rates: Ignoring pool " << pool << " not in 1 .. " << DelayPools::pools());
        return;
    }

    --pool;

    if (!DelayPools::delay_data[pool].theComposite().getRaw()) {
        debugs(3, DBG_CRITICAL, "parse_delay_pool_rates: Ignoring pool " << pool + 1 << " attempt to set rates with class not set");
        return;
    }

    DelayPools::delay_data[pool].parse();
}

void
DelayConfig::parsePoolAccess(ConfigParser &parser)
{
    unsigned short pool;

    ConfigParser::ParseUShort(&pool);

    if (pool < 1 || pool > DelayPools::pools()) {
        debugs(3, DBG_CRITICAL, "parse_delay_pool_rates: Ignoring pool " << pool << " not in 1 .. " << DelayPools::pools());
        return;
    }

    --pool;
    aclParseAccessLine(parser, &DelayPools::delay_data[pool].access);
}

void
DelayConfig::freePoolCount()
{
    DelayPools::FreePools();
    initial = 50;
}

void
DelayConfig::dumpPoolCount(StoreEntry * entry, const char *name) const
{
    int i;

    if (!DelayPools::pools()) {
        storeAppendPrintf(entry, "%s 0\n", name);
        return;
    }

    storeAppendPrintf(entry, "%s %d\n", name, DelayPools::pools());

    for (i = 0; i < DelayPools::pools(); ++i)
        DelayPools::delay_data[i].dump (entry, i);
}

#endif /* USE_DELAY_POOLS */
