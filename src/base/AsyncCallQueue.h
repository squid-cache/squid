/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ASYNCCALLQUEUE_H
#define SQUID_ASYNCCALLQUEUE_H

#include "base/AsyncCall.h"
#include "base/AsyncCallList.h"

//class AsyncCall;

// The queue of asynchronous calls. All calls are fired during a single main
// loop iteration until the queue is exhausted
class AsyncCallQueue
{
public:
    // there is only one queue
    static AsyncCallQueue &Instance();

    // make this async call when we get a chance
    void schedule(AsyncCall::Pointer &call) { list.add(call); }

    // fire all scheduled calls; returns true if at least one was fired
    bool fire();

private:
    AsyncCallQueue();

    AsyncCallList list; ///< scheduled calls in a FIFO list

    static AsyncCallQueue *TheInstance;
};

#endif /* SQUID_ASYNCCALLQUEUE_H */

