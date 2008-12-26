#ifndef SQUID_QOSCONFIG_H
#define SQUID_QOSCONFIG_H

#include "config.h"

#if USE_ZPH_QOS

class StoreEntry;

class QosConfig
{
public:
    int tos_local_hit;
    int tos_sibling_hit;
    int tos_parent_hit;
    int preserve_miss_tos;
    int preserve_miss_tos_mask;

public:
    QosConfig();
    ~QosConfig() {};

    void parseConfigLine();
    void dumpConfigLine(StoreEntry *entry, const char *name) const;
};

/* legacy parser access wrappers */
#define parse_QosConfig(X)	(X)->parseConfigLine()
#define dump_QosConfig(e,n,X)	(X).dumpConfigLine(e,n)
#define free_QosConfig(X)

#endif /* USE_ZPH_QOS */
#endif /* SQUID_QOSCONFIG_H */
