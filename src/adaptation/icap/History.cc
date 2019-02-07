/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "adaptation/icap/History.h"
#include "Debug.h"
#include "globals.h"
#include "SquidTime.h"

Adaptation::Icap::History::History():
    logType(LOG_TAG_NONE),
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

    debugs(93,4, HERE << "start " << context << " level=" << concurrencyLevel
           << " time=" << tvToMsec(pastTime) << ' ' << this);
}

void Adaptation::Icap::History::stop(const char *context)
{
    if (!concurrencyLevel) {
        debugs(93, DBG_IMPORTANT, HERE << "Internal error: poor history accounting " << this);
        return;
    }

    struct timeval current;
    currentTime(current);
    debugs(93,4, HERE << "stop " << context << " level=" << concurrencyLevel <<
           " time=" << tvToMsec(pastTime) << '+' << tvToMsec(current) << ' ' << this);

    if (!--concurrencyLevel)
        tvAssignAdd(pastTime, current);
}

void
Adaptation::Icap::History::processingTime(timeval &total) const
{
    currentTime(total);
    tvAssignAdd(total, pastTime);
    debugs(93,7, HERE << " current total: " << tvToMsec(total) << ' ' << this);
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

