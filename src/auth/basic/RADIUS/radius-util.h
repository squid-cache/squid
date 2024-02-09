/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// 2008-05-14: rename to radius-util.* to avoid name clashes with squid util.*

#ifndef SQUID_SRC_AUTH_BASIC_RADIUS_RADIUS_UTIL_H
#define SQUID_SRC_AUTH_BASIC_RADIUS_RADIUS_UTIL_H

// uses the squid utilities
#include "util.h"

/* util.c */
uint32_t        get_ipaddr (char *);

#endif /* SQUID_SRC_AUTH_BASIC_RADIUS_RADIUS_UTIL_H */

