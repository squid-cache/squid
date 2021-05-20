/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTACTIVEREQUESTS_H
#define SQUID_CLIENTACTIVEREQUESTS_H

#include "dlink.h"

/// Active requests table to be rendered in cache manager
extern dlink_list ClientActiveRequests;

void ClientActiveRequestsInit();

#endif /* SQUID_CLIENTACTIVEREQUESTS_H */

