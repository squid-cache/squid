/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 41    Event Processing */

#include "squid.h"
#include "base/AsyncCall.h"
#include "base/AsyncCallQueue.h"
#include "Debug.h"

AsyncCallQueue *AsyncCallQueue::TheInstance = 0;

AsyncCallQueue::AsyncCallQueue(): theHead(NULL), theTail(NULL)
{
}

void AsyncCallQueue::schedule(AsyncCall::Pointer &call)
{
    assert(call != NULL);
    assert(!call->theNext);
    if (theHead != NULL) { // append
        assert(!theTail->theNext);
        theTail->theNext = call;
        theTail = call;
    } else { // create queue from cratch
        theHead = theTail = call;
    }
}

// Fire all scheduled calls; returns true if at least one call was fired.
// The calls may be added while the current call is in progress.
bool
AsyncCallQueue::fire()
{
    const bool made = theHead != NULL;
    while (theHead != NULL)
        fireNext();
    return made;
}

void
AsyncCallQueue::fireNext()
{
    AsyncCall::Pointer call = theHead;
    theHead = call->theNext;
    call->theNext = NULL;
    if (theTail == call)
        theTail = NULL;

    debugs(call->debugSection, call->debugLevel, "entering " << *call);
    call->make();
    debugs(call->debugSection, call->debugLevel, "leaving " << *call);
}

AsyncCallQueue &
AsyncCallQueue::Instance()
{
    // TODO: how to remove this frequent check while supporting early calls?
    if (!TheInstance)
        TheInstance = new AsyncCallQueue();

    return *TheInstance;
}

