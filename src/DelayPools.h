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

/// \ingroup DelayPoolsAPI
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

