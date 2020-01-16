/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Acl.h"
#include "acl/Gadgets.h"
#include "ClientDelayConfig.h"
#include "ConfigParser.h"
#include "Parsing.h"
#include "Store.h"

void ClientDelayPool::dump(StoreEntry * entry, unsigned int poolNumberMinusOne) const
{
    LOCAL_ARRAY(char, nom, 32);
    snprintf(nom, 32, "client_delay_access %d", poolNumberMinusOne + 1);
    dump_acl_access(entry, nom, access);
    storeAppendPrintf(entry, "client_delay_parameters %d %d %" PRId64 "\n", poolNumberMinusOne + 1, rate,highwatermark);
    storeAppendPrintf(entry, "\n");
}

void
ClientDelayConfig::finalize()
{
    for (unsigned int i = 0; i < pools.size(); ++i) {
        /* pools require explicit 'allow' to assign a client into them */
        if (!pools[i].access) {
            debugs(77, DBG_IMPORTANT, "client_delay_pool #" << (i+1) <<
                   " has no client_delay_access configured. " <<
                   "No client will ever use it.");
        }
    }
}

void ClientDelayConfig::freePoolCount()
{
    pools.clear();
}

void ClientDelayConfig::dumpPoolCount(StoreEntry * entry, const char *name) const
{
    if (pools.size()) {
        storeAppendPrintf(entry, "%s %d\n", name, (int)pools.size());
        for (unsigned int i = 0; i < pools.size(); ++i)
            pools[i].dump(entry, i);
    }
}

void ClientDelayConfig::parsePoolCount()
{
    if (pools.size()) {
        debugs(3, DBG_CRITICAL, "parse_client_delay_pool_count: multiple client_delay_pools lines, aborting all previous client_delay_pools config");
        clean();
    }
    unsigned short pools_;
    ConfigParser::ParseUShort(&pools_);
    for (int i = 0; i < pools_; ++i) {
        pools.push_back(ClientDelayPool());
    }
}

void ClientDelayConfig::parsePoolRates()
{
    unsigned short pool;
    ConfigParser::ParseUShort(&pool);

    if (pool < 1 || pool > pools.size()) {
        debugs(3, DBG_CRITICAL, "parse_client_delay_pool_rates: Ignoring pool " << pool << " not in 1 .. " << pools.size());
        return;
    }

    --pool;

    pools[pool].rate = GetInteger();
    pools[pool].highwatermark = GetInteger64();
}

void ClientDelayConfig::parsePoolAccess(ConfigParser &parser)
{
    unsigned short pool;

    ConfigParser::ParseUShort(&pool);

    if (pool < 1 || pool > pools.size()) {
        debugs(3, DBG_CRITICAL, "parse_client_delay_pool_rates: Ignoring pool " << pool << " not in 1 .. " << pools.size());
        return;
    }

    --pool;
    aclParseAccessLine("client_delay_access", parser, &pools[pool].access);
}

void ClientDelayConfig::clean()
{
    for (unsigned int i = 0; i < pools.size(); ++i) {
        aclDestroyAccessList(&pools[i].access);
    }
}

