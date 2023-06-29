/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "acl/Gadgets.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "DelaySpec.h"
#include "event.h"
#include "MessageBucket.h"
#include "MessageDelayPools.h"
#include "Parsing.h"
#include "Store.h"

#include <algorithm>
#include <map>

MessageDelayPools::~MessageDelayPools()
{
    freePools();
}

MessageDelayPools *
MessageDelayPools::Instance()
{
    static MessageDelayPools pools;
    return &pools;
}

MessageDelayPool::Pointer
MessageDelayPools::pool(const SBuf &name)
{
    auto it = std::find_if(pools.begin(), pools.end(),
    [&name](const MessageDelayPool::Pointer p) { return p->poolName == name; });
    return it == pools.end() ? nullptr : *it;
}

void
MessageDelayPools::add(MessageDelayPool *p)
{
    const auto it = std::find_if(pools.begin(), pools.end(),
    [&p](const MessageDelayPool::Pointer mp) { return mp->poolName == p->poolName; });
    if (it != pools.end()) {
        debugs(3, DBG_CRITICAL, "WARNING: Ignoring duplicate " << p->poolName << " response delay pool");
        return;
    }
    pools.push_back(p);
}

void
MessageDelayPools::freePools()
{
    pools.clear();
}

MessageDelayPool::MessageDelayPool(const SBuf &name, int64_t bucketSpeed, int64_t bucketSize,
                                   int64_t aggregateSpeed, int64_t aggregateSize, uint16_t initialBucketPercent):
    access(nullptr),
    poolName(name),
    individualRestore(bucketSpeed),
    individualMaximum(bucketSize),
    aggregateRestore(aggregateSpeed),
    aggregateMaximum(aggregateSize),
    initialBucketLevel(initialBucketPercent),
    lastUpdate(squid_curtime)
{
    theBucket.level() = aggregateMaximum;
}

MessageDelayPool::~MessageDelayPool()
{
    if (access)
        aclDestroyAccessList(&access);
}

void
MessageDelayPool::refillBucket()
{
    if (noLimit())
        return;
    const int incr = squid_curtime - lastUpdate;
    if (incr >= 1) {
        lastUpdate = squid_curtime;
        DelaySpec spec;
        spec.restore_bps = aggregateRestore;
        spec.max_bytes = aggregateMaximum;
        theBucket.update(spec, incr);
    }
}

void
MessageDelayPool::dump(StoreEntry *entry) const
{
    SBuf name("response_delay_pool_access ");
    name.append(poolName);
    dump_acl_access(entry, name.c_str(), access);
    storeAppendPrintf(entry, "response_delay_pool parameters %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %d\n",
                      individualRestore, individualMaximum, aggregateRestore, aggregateMaximum, initialBucketLevel);
    storeAppendPrintf(entry, "\n");
}

MessageBucket::Pointer
MessageDelayPool::createBucket()
{
    return new MessageBucket(individualRestore, initialBucketLevel, individualMaximum, this);
}

void
MessageDelayConfig::parseResponseDelayPool()
{
    static const SBuf bucketSpeedLimit("individual-restore");
    static const SBuf maxBucketSize("individual-maximum");
    static const SBuf aggregateSpeedLimit("aggregate-restore");
    static const SBuf maxAggregateSize("aggregate-maximum");
    static const SBuf initialBucketPercent("initial-bucket-level");

    static std::map<SBuf, int64_t> params;
    params[bucketSpeedLimit] = -1;
    params[maxBucketSize] = -1;
    params[aggregateSpeedLimit] = -1;
    params[maxAggregateSize] = -1;
    params[initialBucketPercent] = 50;

    const SBuf name(ConfigParser::NextToken());
    if (name.isEmpty()) {
        debugs(3, DBG_CRITICAL, "FATAL: response_delay_pool missing required \"name\" parameter.");
        self_destruct();
        return;
    }

    char *key = nullptr;
    char *value = nullptr;
    while (ConfigParser::NextKvPair(key, value)) {
        if (!value) {
            debugs(3, DBG_CRITICAL, "FATAL: '" << key << "' option missing value");
            self_destruct();
            return;
        }
        auto it = params.find(SBuf(key));
        if (it == params.end()) {
            debugs(3, DBG_CRITICAL, "FATAL: response_delay_pool unknown option '" << key << "'");
            self_destruct();
            return;
        }
        it->second = (it->first == initialBucketPercent) ? xatos(value) : xatoll(value, 10);
    }

    const char *fatalMsg = nullptr;
    if ((params[bucketSpeedLimit] < 0) != (params[maxBucketSize] < 0))
        fatalMsg = "'individual-restore' and 'individual-maximum'";
    else if ((params[aggregateSpeedLimit] < 0) != (params[maxAggregateSize] < 0))
        fatalMsg = "'aggregate-restore' and 'aggregate-maximum'";

    if (fatalMsg) {
        debugs(3, DBG_CRITICAL, "FATAL: must use " << fatalMsg << " options in conjunction");
        self_destruct();
        return;
    }

    MessageDelayPool *pool = new MessageDelayPool(name,
            params[bucketSpeedLimit],
            params[maxBucketSize],
            params[aggregateSpeedLimit],
            params[maxAggregateSize],
            static_cast<uint16_t>(params[initialBucketPercent])
                                                 );
    MessageDelayPools::Instance()->add(pool);
}

void
MessageDelayConfig::parseResponseDelayPoolAccess() {
    const char *token = ConfigParser::NextToken();
    if (!token) {
        debugs(3, DBG_CRITICAL, "ERROR: required pool_name option missing");
        return;
    }
    MessageDelayPool::Pointer pool = MessageDelayPools::Instance()->pool(SBuf(token));
    static ConfigParser parser;
    if (pool)
        aclParseAccessLine("response_delay_pool_access", parser, &pool->access);
}

void
MessageDelayConfig::freePools()
{
    MessageDelayPools::Instance()->freePools();
}

void
MessageDelayConfig::dumpResponseDelayPoolParameters(StoreEntry *entry)
{
    auto &pools = MessageDelayPools::Instance()->pools;
    for (auto pool: pools)
        pool->dump(entry);
}

#endif

