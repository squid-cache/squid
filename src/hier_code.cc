#include "config.h"
#include "hier_code.h"

const char *hier_strings[] = {
    "NONE",          /* HIER_NONE */
    "DIRECT",        /* HIER_DIRECT */
    "SIBLING_HIT",
    "PARENT_HIT",
    "DEFAULT_PARENT",
    "SINGLE_PARENT",
    "FIRSTUP_PARENT",
    "FIRST_PARENT_MISS",
    "CLOSEST_PARENT_MISS",
    "CLOSEST_PARENT",
    "CLOSEST_DIRECT",
    "NO_DIRECT_FAIL",
    "SOURCE_FASTEST",
    "ROUNDROBIN_PARENT",
#if USE_CACHE_DIGESTS
    "CD_PARENT_HIT",
    "CD_SIBLING_HIT",
#endif
    "CARP",
    "ANY_PARENT",
    "USERHASH",
    "SOURCEHASH",
    "PINNED",
    "HIER_MAX"
};
