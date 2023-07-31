/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/History.h"
#include "debug/Stream.h"
#include "globals.h"
#include "time/gadgets.h"

Adaptation::Icap::History::History():
    req_sz(0),
    concurrencyLevel(0)
{
    memset(&currentStart, 0, sizeof(currentStart));
    memset(&pastTime, 0, sizeof(pastTime));
}

void Adaptation::Icap::History::start(const char *context)
{
    if (!concurrencyLevel++)
        currentStart = current_time;

    debugs(93,4, "start " << context << " level=" << concurrencyLevel
           << " time=" << tvToMsec(pastTime) << ' ' << this);
}

void Adaptation::Icap::History::stop(const char *context)
{
    if (!concurrencyLevel) {
        debugs(93, DBG_IMPORTANT, "ERROR: Squid BUG: poor history accounting " << this);
        return;
    }

    struct timeval current;
    currentTime(current);
    debugs(93,4, "stop " << context << " level=" << concurrencyLevel <<
           " time=" << tvToMsec(pastTime) << '+' << tvToMsec(current) << ' ' << this);

    if (!--concurrencyLevel)
        tvAssignAdd(pastTime, current);
}

void
Adaptation::Icap::History::processingTime(timeval &total) const
{
    currentTime(total);
    tvAssignAdd(total, pastTime);
    debugs(93,7, " current total: " << tvToMsec(total) << ' ' << this);
}

void
Adaptation::Icap::History::currentTime(timeval &current) const
{
    if (concurrencyLevel > 0)
        tvSub(current, currentStart, current_time);
    else {
        current.tv_sec = 0;
        current.tv_usec = 0;
    }
}

