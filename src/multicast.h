/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 07    Multicast */

#ifndef SQUID_MULTICAST_H_
#define SQUID_MULTICAST_H_

#include "ipcache.h"

int mcastSetTtl(int, int);
extern IPH mcastJoinGroups;

#endif /* SQUID_MULTICAST_H_ */

