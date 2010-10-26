#ifndef SQUID_CLIENTDELAYCONFIG_H
#define SQUID_CLIENTDELAYCONFIG_H

#include "Array.h"
class StoreEntry;
class acl_access;
class ConfigParser;

/// \ingroup DelayPoolsAPI

/* represents one client write limiting delay 'pool' */
class ClientDelayPool
{
public:
    ClientDelayPool()
            :   access(NULL), rate(0), highwatermark(0) {}
    void dump (StoreEntry * entry, unsigned int poolNumberMinusOne) const;
    acl_access *access;
    int rate;
    int64_t highwatermark;
};

typedef Vector<ClientDelayPool> ClientDelayPools;

/* represents configuration of client write limiting delay pools */
class ClientDelayConfig
{
public:
    ClientDelayConfig()
            :   initial(50) {}
    void freePoolCount();
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
    ClientDelayPools pools;
private:
    void clean();
};

#endif // SQUID_CLIENTDELAYCONFIG_H
