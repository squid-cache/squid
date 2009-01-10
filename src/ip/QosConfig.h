#ifndef SQUID_QOSCONFIG_H
#define SQUID_QOSCONFIG_H

#include "config.h"

#if USE_ZPH_QOS

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
    void dumpConfigLine(char *entry, const char *name) const;
};

/* legacy parser access wrappers */
#define parse_QosConfig(X)	(X)->parseConfigLine()
#define free_QosConfig(X)
#define dump_QosConfig(e,n,X) do { \
		char temp[256]; /* random number. change as needed. max config line length. */ \
		(X).dumpConfigLine(temp,n); \
	        storeAppendPrintf(e, "%s", temp); \
	} while(0);

#endif /* USE_ZPH_QOS */
#endif /* SQUID_QOSCONFIG_H */
