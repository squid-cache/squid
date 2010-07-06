#ifndef SQUID_QOSCONFIG_H
#define SQUID_QOSCONFIG_H

#include "config.h"

#if USE_ZPH_QOS

namespace Ip
{

namespace Qos
{

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

extern QosConfig TheConfig;

/* legacy parser access wrappers */
#define parse_QosConfig(X)	(X)->parseConfigLine()
#define free_QosConfig(X)
#define dump_QosConfig(e,n,X) do { \
		char temp[256]; /* random number. change as needed. max config line length. */ \
		(X).dumpConfigLine(temp,n); \
	        storeAppendPrintf(e, "%s", temp); \
	} while(0);

}; // namespace Qos
}; // namespace Ip

#endif /* USE_ZPH_QOS */
#endif /* SQUID_QOSCONFIG_H */
