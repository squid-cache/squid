/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 07    Multicast */

#ifndef SQUID_SRC_MULTICAST_H
#define SQUID_SRC_MULTICAST_H

#include "ipcache.h"

int mcastSetTtl(int, int);
extern IPH mcastJoinGroups;

#endif /* SQUID_SRC_MULTICAST_H */

