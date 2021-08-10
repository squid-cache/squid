/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

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
    aclParseAccessLine("delay_access", parser, &DelayPools::delay_data[pool].access);
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

