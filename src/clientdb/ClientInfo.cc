/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Client Database */

#include "squid.h"
#include "clientdb/ClientInfo.h"
#include "Debug.h"

ClientInfo::ClientInfo(const Ip::Address &ip) :
#if USE_DELAY_POOLS
    BandwidthBucket(0, 0, 0),
#endif
    addr(ip)
{
    debugs(77, 9, "ClientInfo constructed, this=" << static_cast<void*>(this));
}

ClientInfo::~ClientInfo()
{
#if USE_DELAY_POOLS
    if (CommQuotaQueue *q = quotaQueue) {
        q->clientInfo = NULL;
        delete q; // invalidates cbdata, cancelling any pending kicks
    }
#endif

    debugs(77, 9, "ClientInfo destructed, this=" << static_cast<void*>(this));
}

