/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 41    Event Processing */

#include "squid.h"
#include "base/AsyncCall.h"
#include "base/AsyncCallQueue.h"
#include "debug/Stream.h"

AsyncCallQueue *AsyncCallQueue::TheInstance = nullptr;

// Fire all scheduled calls; returns true if at least one call was fired.
// The calls may be added while the current call is in progress.
bool
AsyncCallQueue::fire()
{
    const auto made = scheduled.size() > 0;
    while (const auto call = scheduled.extract()) {
        CodeContext::Reset(call->codeContext);
        debugs(call->debugSection, call->debugLevel, "entering " << *call);
        call->make();
        debugs(call->debugSection, call->debugLevel, "leaving " << *call);
    }
    if (made)
        CodeContext::Reset();
    return made;
}

AsyncCallQueue &
AsyncCallQueue::Instance()
{
    // TODO: how to remove this frequent check while supporting early calls?
    if (!TheInstance)
        TheInstance = new AsyncCallQueue();

    return *TheInstance;
}

