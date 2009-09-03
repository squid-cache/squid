#ifndef _SQUID_LOOKUP_T_H
#define _SQUID_LOOKUP_T_H

typedef enum {
    LOOKUP_NONE,
    LOOKUP_HIT,
    LOOKUP_MISS
} lookup_t;

extern const char *lookup_t_str[];

#endif /* _SQUID_LOOKUP_T_H */
