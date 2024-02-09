/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ASYNCCALLQUEUE_H
#define SQUID_SRC_BASE_ASYNCCALLQUEUE_H

#include "base/AsyncCallList.h"
#include "base/forward.h"

// The queue of asynchronous calls. All calls are fired during a single main
// loop iteration until the queue is exhausted
class AsyncCallQueue
{
public:
    // there is only one queue
    static AsyncCallQueue &Instance();

    // make this async call when we get a chance
    void schedule(const AsyncCallPointer &call) { scheduled.add(call); }

    // fire all scheduled calls; returns true if at least one was fired
    bool fire();

private:
    AsyncCallQueue() = default;

    AsyncCallList scheduled; ///< calls waiting to be fire()d, in FIFO order

    static AsyncCallQueue *TheInstance;
};

#endif /* SQUID_SRC_BASE_ASYNCCALLQUEUE_H */

