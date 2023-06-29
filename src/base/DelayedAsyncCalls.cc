/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/AsyncCall.h"
#include "base/DelayedAsyncCalls.h"
#include "debug/Stream.h"

void
DelayedAsyncCalls::delay(const AsyncCall::Pointer &call)
{
    debugs(5, 3, call << " after " << deferredReads.size());
    deferredReads.add(call);
}

void
DelayedAsyncCalls::schedule()
{
    while (auto call = deferredReads.extract())
        ScheduleCallHere(call);
}

