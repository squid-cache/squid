/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTDELAYCONFIG_H
#define SQUID_SRC_CLIENTDELAYCONFIG_H

#include "acl/forward.h"
#include "base/RefCount.h"

#include <vector>

class StoreEntry;
class ConfigParser;

/// \ingroup DelayPoolsAPI

/* represents one client write limiting delay 'pool' */
class ClientDelayPool : public RefCountable
{
public:
    typedef RefCount<ClientDelayPool> Pointer;

    ClientDelayPool()
        :   access(nullptr), rate(0), highwatermark(0) {}
    ~ClientDelayPool() override;
    ClientDelayPool(const ClientDelayPool &) = delete;
    ClientDelayPool &operator=(const ClientDelayPool &) = delete;

    void dump (StoreEntry * entry, unsigned int poolNumberMinusOne) const;
    acl_access *access;
    int rate;
    int64_t highwatermark;
};

class ClientDelayPools
{
public:
    ClientDelayPools(const ClientDelayPools &) = delete;
    ClientDelayPools &operator=(const ClientDelayPools &) = delete;
    static ClientDelayPools *Instance();

    std::vector<ClientDelayPool::Pointer> pools;
private:
    ClientDelayPools() {}
    ~ClientDelayPools();
};

/* represents configuration of client write limiting delay pools */
class ClientDelayConfig
{
public:
    ClientDelayConfig()
        :   initial(50) {}
    ClientDelayConfig(const ClientDelayConfig &) = delete;
    ClientDelayConfig &operator=(const ClientDelayConfig &) = delete;

    void freePools();
    void dumpPoolCount(StoreEntry * entry, const char *name) const;
    /* parsing of client_delay_pools - number of pools */
    void parsePoolCount();
    /* parsing of client_delay_parameters lines */
    void parsePoolRates();
    /* parsing client_delay_access lines */
    void parsePoolAccess(ConfigParser &parser);

    void finalize(); ///< checks pools configuration

    /* initial bucket level, how fill bucket at startup */
    unsigned short initial;

private:
    unsigned short parsePoolId();
    std::vector<ClientDelayPool::Pointer> &pools() { return ClientDelayPools::Instance()->pools; }
    ClientDelayPool &pool(const int i) { return *(ClientDelayPools::Instance()->pools.at(i)); }
};

#endif /* SQUID_SRC_CLIENTDELAYCONFIG_H */

