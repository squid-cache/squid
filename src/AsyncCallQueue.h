
/*
 * $Id: AsyncCallQueue.h,v 1.1 2008/02/13 06:01:39 rousskov Exp $
 *
 */

#ifndef SQUID_ASYNCCALLQUEUE_H
#define SQUID_ASYNCCALLQUEUE_H

#include "squid.h"
#include "AsyncCall.h"

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
