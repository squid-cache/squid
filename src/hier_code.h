/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__HIER_CODE_H
#define SQUID__HIER_CODE_H

typedef enum {
    HIER_NONE,
    HIER_DIRECT,
    SIBLING_HIT,
    PARENT_HIT,
    DEFAULT_PARENT,
    SINGLE_PARENT,
    FIRSTUP_PARENT,
    FIRST_PARENT_MISS,
    CLOSEST_PARENT_MISS,
    CLOSEST_PARENT,
    CLOSEST_DIRECT,
    NO_DIRECT_FAIL,
    SOURCE_FASTEST,
    ROUNDROBIN_PARENT,
#if USE_CACHE_DIGESTS
    CD_PARENT_HIT,
    CD_SIBLING_HIT,
#endif
    CARP,
    ANY_OLD_PARENT,
    USERHASH_PARENT,
    SOURCEHASH_PARENT,
    PINNED,
    ORIGINAL_DST,
    STANDBY_POOL,
    HIER_MAX
} hier_code;

extern const char *hier_code_str[];

inline hier_code operator++(hier_code &i) { return i = (hier_code)(1+(int)i); }

#endif /* SQUID__HIER_CODE_H */

