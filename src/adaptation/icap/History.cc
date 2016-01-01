/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
    pastTime(0),
    concurrencyLevel(0)
{
    memset(&currentStart, 0, sizeof(currentStart));
}

void Adaptation::Icap::History::start(const char *context)
{
    if (!concurrencyLevel++)
        currentStart = current_time;

    debugs(93,4, HERE << "start " << context << " level=" << concurrencyLevel
           << " time=" << pastTime << ' ' << this);
}

void Adaptation::Icap::History::stop(const char *context)
{
    if (!concurrencyLevel) {
        debugs(93, DBG_IMPORTANT, HERE << "Internal error: poor history accounting " << this);
        return;
    }

    const int current = currentTime();
    debugs(93,4, HERE << "stop " << context << " level=" << concurrencyLevel <<
           " time=" << pastTime << '+' << current << ' ' << this);

    if (!--concurrencyLevel)
        pastTime += current;
}

int Adaptation::Icap::History::processingTime() const
{
    const int total = pastTime + currentTime();
    debugs(93,7, HERE << " current total: " << total << ' ' << this);
    return total;
}

int Adaptation::Icap::History::currentTime() const
{
    return concurrencyLevel > 0 ?
           max(0, tvSubMsec(currentStart, current_time)) : 0;
}

