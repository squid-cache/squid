/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ASYNCCALLQUEUE_H
#define SQUID_ASYNCCALLQUEUE_H

#include "base/AsyncCall.h"

//class AsyncCall;

// The queue of asynchronous calls. All calls are fired during a single main
// loop iteration until the queue is exhausted
class AsyncCallQueue
{
public:
    // there is only one queue
    static AsyncCallQueue &Instance();

    // make this async call when we get a chance
    void schedule(AsyncCall::Pointer &call);

    // fire all scheduled calls; returns true if at least one was fired
    bool fire();

private:
    AsyncCallQueue();

    void fireNext();

    AsyncCall::Pointer theHead;
    AsyncCall::Pointer theTail;

    static AsyncCallQueue *TheInstance;
};

#endif /* SQUID_ASYNCCALLQUEUE_H */

