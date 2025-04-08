/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DELAYPOOLS_H
#define SQUID_SRC_DELAYPOOLS_H

#include <vector>

class DelayPool;
class Updateable;
class StoreEntry;

/**
 \defgroup DelayPoolsAPI Delay Pools API
 \ingroup Components
 */

/// \ingroup DelayPoolsAPI
class Updateable
{

public:
    virtual ~Updateable() {}

    virtual void update(int) = 0;
};

/**
\ingroup DelayPoolsAPI

\par
    Delay Pools is a Squid feature implementing simple Traffic Management
    controls similar to Quality of Service (QoS). It limits the size of
    network I/O read and write operations for a group of HTTP transactions
    defined by ACL matching.
    \see https://squid-cache.org/Doc/config/delay_access
    \see https://squid-cache.org/Doc/config/client_delay_access

\par
    A DelayPool is a Composite used to manage bandwidth for any request
    assigned to the pool by an access expression. DelayId's are a used
    to manage the bandwidth on a given request, whereas a DelayPool
    manages the bandwidth availability and assigned DelayId's.

\section ExtendingDelayPools Extending Delay Pools
\par
    A CompositePoolNode is the base type for all members of a DelayPool.
    Any child must implement the RefCounting primitives, as well as five
    delay pool functions:
    \li     stats() - provide cachemanager statistics for itself.
    \li     dump() - generate squid.conf syntax for the current configuration of the item.
    \li     update() - allocate more bandwidth to all buckets in the item.
    \li     parse() - accept squid.conf syntax for the item, and configure for use appropriately.
    \li     id() - return a DelayId entry for the current item.

\par
    A DelayIdComposite is the base type for all delay Id's. Concrete
    Delay Id's must implement the refcounting primitives, as well as two
    delay id functions:
    \li     bytesWanted() - return the largest amount of bytes that this delay id allows by policy.
    \li     bytesIn() - record the use of bandwidth by the request(s) that this delayId is monitoring.

\par
    Composite creation is currently under design review, so see the
    DelayPool class and follow the parse() code path for details.

\section NeatExtensions Neat things that could be done.
\par
    With the composite structure, some neat things have become possible.
    For instance:

\par    Dynamically defined pool arrangements.
        For instance an aggregate (class 1) combined with the per-class-C-net tracking of a
        class 3 pool, without the individual host tracking. This differs
        from a class 3 pool with -1/-1 in the host bucket, because no memory
        or cpu would be used on hosts, whereas with a class 3 pool, they are
        allocated and used.

\par    Per request bandwidth limits.
        A delayId that contains it's own bucket could limit each request
        independently to a given policy, with no aggregate restrictions.
*/
class DelayPools
{

public:
    static void Init();
    static void Update(void *);
    static unsigned short pools();
    static void pools(unsigned short pools);
    static void FreePools();
    static unsigned char *DelayClasses();
    static void registerForUpdates(Updateable *);
    static void deregisterForUpdates (Updateable *);
    static DelayPool *delay_data;

private:
    static void Stats(StoreEntry *);
    static void InitDelayData();
    static time_t LastUpdate;
    static unsigned short pools_;
    static void FreeDelayData ();
    static std::vector<Updateable *> toUpdate;
    static void RegisterWithCacheManager(void);
};

#endif /* SQUID_SRC_DELAYPOOLS_H */

