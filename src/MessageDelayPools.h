/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef MESSAGEDELAYPOOLS_H
#define MESSAGEDELAYPOOLS_H

#if USE_DELAY_POOLS

#include "acl/Acl.h"
#include "base/RefCount.h"
#include "DelayBucket.h"
#include "DelayPools.h"
#include "sbuf/SBuf.h"

class MessageBucket;
typedef RefCount<MessageBucket> MessageBucketPointer;

/// \ingroup DelayPoolsAPI
/// Represents one 'response' delay pool, creates individual response
/// buckets and performes aggregate limiting for them
class MessageDelayPool : public RefCountable
{
public:
    typedef RefCount<MessageDelayPool> Pointer;

    MessageDelayPool(const SBuf &name, int64_t bucketSpeed, int64_t bucketSize,
                     int64_t aggregateSpeed, int64_t aggregateSize, uint16_t initialBucketPercent);
    ~MessageDelayPool();
    MessageDelayPool(const MessageDelayPool &) = delete;
    MessageDelayPool &operator=(const MessageDelayPool &) = delete;

    /// Increases the aggregate bucket level with the aggregateRestore speed.
    void refillBucket();
    /// decreases the aggregate level
    void bytesIn(int qty) { if (!noLimit()) theBucket.bytesIn(qty); }
    /// current aggregate level
    int level() { return theBucket.level(); }
    /// creates an individual response bucket
    MessageBucketPointer createBucket();
    /// whether the aggregate bucket has no limit
    bool noLimit () const { return aggregateRestore < 0; }

    void dump (StoreEntry * entry) const;

    acl_access *access;
    /// the response delay pool name
    SBuf poolName;
    /// the speed limit of an individual bucket (bytes/s)
    int64_t individualRestore;
    /// the maximum size of an individual bucket
    int64_t individualMaximum;
    /// the speed limit of the aggregate bucket (bytes/s)
    int64_t aggregateRestore;
    /// the maximum size of the aggregate bucket
    int64_t aggregateMaximum;
    /// the initial bucket size as a percentage of individualMaximum
    uint16_t initialBucketLevel;
    /// the aggregate bucket
    DelayBucket theBucket;

private:
    /// Time the aggregate bucket level was last refilled.
    time_t lastUpdate;
};

/// \ingroup DelayPoolsAPI
/// represents all configured 'response' delay pools
class MessageDelayPools
{
public:
    MessageDelayPools(const MessageDelayPools &) = delete;
    MessageDelayPools &operator=(const MessageDelayPools &) = delete;

    static MessageDelayPools *Instance();

    /// returns a MessageDelayPool with a given name or null otherwise
    MessageDelayPool::Pointer pool(const SBuf &name);
    /// appends a single MessageDelayPool, created during configuration
    void add(MessageDelayPool *pool);
    /// memory cleanup, performing during reconfiguration
    void freePools();

    std::vector<MessageDelayPool::Pointer> pools;

private:
    MessageDelayPools() {}
    ~MessageDelayPools();
    void Stats() { } // TODO
};

/// represents configuration for response delay pools
class MessageDelayConfig
{
public:
    void parseResponseDelayPool();
    void dumpResponseDelayPoolParameters(StoreEntry *e, const char *name);
    void parseResponseDelayPoolAccess();
    void freePools();
};

#define free_response_delay_pool_access(X)
#define dump_response_delay_pool_access(X, Y, Z)

inline void
free_response_delay_pool_parameters(MessageDelayConfig * cfg)
{
    cfg->freePools();
}

inline void
dump_response_delay_pool_parameters(StoreEntry *entry, const char *name, MessageDelayConfig &cfg)
{
    cfg.dumpResponseDelayPoolParameters(entry, name);
}

inline void
parse_response_delay_pool_parameters(MessageDelayConfig * cfg)
{
    cfg->parseResponseDelayPool();
}

inline void
parse_response_delay_pool_access(MessageDelayConfig * cfg)
{
    cfg->parseResponseDelayPoolAccess();
}

#endif
#endif

