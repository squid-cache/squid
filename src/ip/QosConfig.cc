#include "squid.h"

#if USE_ZPH_QOS

#include "QosConfig.h"
#include "Store.h"

QosConfig::QosConfig() : 
	tos_local_hit(0),
	tos_sibling_hit(0),
	tos_parent_hit(0),
	preserve_miss_tos(1),
	preserve_miss_tos_mask(255)
{
    ;
}

void
QosConfig::parseConfigLine()
{
    // %i honors 0 and 0x prefixes, which are important for things like umask
    /* parse options ... */
    char *token;
    while( (token = strtok(NULL, w_space)) ) {

        if(strncmp(token, "local-hit=",10) == 0) {
            sscanf(&token[10], "%i", &tos_local_hit);
        }
        else if(strncmp(token, "sibling-hit=",12) == 0) {
            sscanf(&token[12], "%i", &tos_sibling_hit);
        }
        else if(strncmp(token, "parent-hit=",11) == 0) {
            sscanf(&token[11], "%i", &tos_parent_hit);
        }
        else if(strcmp(token, "disable-preserve-miss") == 0) {
            preserve_miss_tos = 0;
            preserve_miss_tos_mask = 0;
        }
        else if(preserve_miss_tos && strncmp(token, "miss-mask=",10) == 0) {
            sscanf(&token[10], "%i", &preserve_miss_tos_mask);
        }
    }
}

void
QosConfig::dumpConfigLine(StoreEntry * entry, const char *name) const
{
    storeAppendPrintf(entry, "%s", name);

    if (tos_local_hit >0) {
        storeAppendPrintf(entry, " local-hit=%2x", tos_local_hit);
    }

    if (tos_sibling_hit >0) {
        storeAppendPrintf(entry, " sibling-hit=%2x", tos_sibling_hit);
    }
    if (tos_parent_hit >0) {
        storeAppendPrintf(entry, " parent-hit=%2x", tos_parent_hit);
    }
    if (preserve_miss_tos != 0) {
        storeAppendPrintf(entry, " disable-preserve-miss");
    }
    if (preserve_miss_tos && preserve_miss_tos_mask != 0) {
        storeAppendPrintf(entry, " miss-mask=%2x", preserve_miss_tos_mask);
    }
    storeAppendPrintf(entry, "\n");
}

#endif /* USE_ZPH_QOS */
