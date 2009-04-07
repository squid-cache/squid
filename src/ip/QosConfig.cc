#include "squid.h"

#if USE_ZPH_QOS

#include "QosConfig.h"

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
    while ( (token = strtok(NULL, w_space)) ) {

        if (strncmp(token, "local-hit=",10) == 0) {
            sscanf(&token[10], "%i", &tos_local_hit);
        } else if (strncmp(token, "sibling-hit=",12) == 0) {
            sscanf(&token[12], "%i", &tos_sibling_hit);
        } else if (strncmp(token, "parent-hit=",11) == 0) {
            sscanf(&token[11], "%i", &tos_parent_hit);
        } else if (strcmp(token, "disable-preserve-miss") == 0) {
            preserve_miss_tos = 0;
            preserve_miss_tos_mask = 0;
        } else if (preserve_miss_tos && strncmp(token, "miss-mask=",10) == 0) {
            sscanf(&token[10], "%i", &preserve_miss_tos_mask);
        }
    }
}

/**
 * NOTE: Due to the low-level nature of the library these
 * objects are part of the dump function must be self-contained.
 * which means no StoreEntry refrences. Just a basic char* buffer.
 */
void
QosConfig::dumpConfigLine(char *entry, const char *name) const
{
    char *p = entry;
    snprintf(p, 10, "%s", name); // strlen("qos_flows ");
    p += strlen(name);

    if (tos_local_hit >0) {
        snprintf(p, 15, " local-hit=%2x", tos_local_hit);
        p += 15;
    }

    if (tos_sibling_hit >0) {
        snprintf(p, 17, " sibling-hit=%2x", tos_sibling_hit);
        p += 17;
    }
    if (tos_parent_hit >0) {
        snprintf(p, 16, " parent-hit=%2x", tos_parent_hit);
        p += 16;
    }
    if (preserve_miss_tos != 0) {
        snprintf(p, 22, " disable-preserve-miss");
        p += 22;
    }
    if (preserve_miss_tos && preserve_miss_tos_mask != 0) {
        snprintf(p, 15, " miss-mask=%2x", preserve_miss_tos_mask);
        p += 15;
    }
    snprintf(p, 1, "\n");
//    p += 1;
}

#endif /* USE_ZPH_QOS */
